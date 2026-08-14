import subprocess
import urllib.request
import json
import ipaddress
import bisect
import sys


EXCLUDED_IPSETS = {
    "i360.ipv4.whitelist.static",
}


SOURCES = {
    "Googlebot": {
        "type": "json",
        "url": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    },
    "Bingbot": {
        "type": "json",
        "url": "https://www.bing.com/toolbox/bingbot.json",
    },
    "PerplexityBot": {
        "type": "json",
        "url": "https://www.perplexity.com/perplexitybot.json",
    },
    "GPTBot": {
        "type": "json",
        "url": "https://openai.com/gptbot.json",
    },
    "Anthropic": {
        "type": "static",
        "ranges": [
            "160.79.104.0/23",
            "160.79.104.0/21",
        ],
    },
}


def download_json(url):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0"
        }
    )

    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def load_bot_ranges(bot_name):
    source = SOURCES[bot_name]
    ranges = []

    if source["type"] == "static":
        for cidr in source["ranges"]:
            try:
                network = ipaddress.ip_network(
                    cidr,
                    strict=False
                )

                if network.version == 4:
                    ranges.append(network)

            except ValueError:
                pass

        return ranges

    try:
        data = download_json(
            source["url"]
        )

    except Exception as e:
        print(
            f"[ERROR] No se pudo obtener "
            f"{bot_name}: {e}"
        )
        return []

    for prefix in data.get("prefixes", []):

        cidr = prefix.get("ipv4Prefix")

        if not cidr:
            continue

        try:
            network = ipaddress.ip_network(
                cidr,
                strict=False
            )

            if network.version == 4:
                ranges.append(network)

        except ValueError:
            pass

    return ranges


def get_ipsets():
    try:
        output = subprocess.check_output(
            ["ipset", "save"],
            text=True,
            stderr=subprocess.DEVNULL
        )

    except Exception as e:
        print(
            f"[ERROR] No se pudo ejecutar "
            f"ipset save: {e}"
        )
        sys.exit(1)

    entries = []

    for line in output.splitlines():

        if not line.startswith("add "):
            continue

        parts = line.split()

        if len(parts) < 3:
            continue

        ipset_name = parts[1]

        if ipset_name in EXCLUDED_IPSETS:
            continue

        entry_raw = parts[2]

        # Soporta:
        # 1.2.3.4
        # 1.2.3.0/24
        # 1.2.3.4,tcp:80
        # 1.2.3.0/24,tcp:443
        entry = entry_raw.split(",")[0]

        # Ignorar IPv6 inmediatamente
        if ":" in entry:
            continue

        try:

            if "/" in entry:

                network = ipaddress.ip_network(
                    entry,
                    strict=False
                )

            else:

                address = ipaddress.ip_address(
                    entry
                )

                if address.version != 4:
                    continue

                network = ipaddress.ip_network(
                    f"{entry}/32",
                    strict=False
                )

        except ValueError:
            continue

        if network.version != 4:
            continue

        entries.append({
            "ipset": ipset_name,
            "entry_raw": entry_raw,
            "network": network,
        })

    return entries


def build_indexes(search_groups):
    indexes = {}

    for bot, ranges in search_groups.items():

        intervals = []

        for network in ranges:

            if network.version != 4:
                continue

            intervals.append(
                (
                    int(network.network_address),
                    int(network.broadcast_address),
                    str(network)
                )
            )

        intervals.sort(
            key=lambda x: x[0]
        )

        indexes[bot] = {
            "intervals": intervals,
            "starts": [
                item[0]
                for item in intervals
            ]
        }

    return indexes


def find_overlap(candidate, index):
    intervals = index["intervals"]
    starts = index["starts"]

    if not intervals:
        return None

    candidate_start = int(
        candidate.network_address
    )

    candidate_end = int(
        candidate.broadcast_address
    )

    pos = bisect.bisect_right(
        starts,
        candidate_end
    )

    i = pos - 1

    while i >= 0:

        start, end, cidr = intervals[i]

        if end < candidate_start:
            break

        if (
            start <= candidate_end
            and end >= candidate_start
        ):
            return cidr

        i -= 1

    return None


def search_ranges(
    search_groups,
    ipset_entries
):
    matches = []

    indexes = build_indexes(
        search_groups
    )

    total = len(ipset_entries)

    for counter, item in enumerate(
        ipset_entries,
        start=1
    ):

        candidate = item["network"]

        for bot, index in indexes.items():

            official_range = find_overlap(
                candidate,
                index
            )

            if official_range:

                matches.append({
                    "bot": bot,
                    "range": official_range,
                    "ipset": item["ipset"],
                    "entry": item["entry_raw"],
                })

        if counter % 100000 == 0:
            print(
                f"  Procesadas "
                f"{counter:,} / "
                f"{total:,} entradas..."
            )

    return matches


def print_results(matches):
    if not matches:
        print()
        print(
            "No se encontraron coincidencias."
        )
        return

    matches.sort(
        key=lambda x: (
            x["bot"],
            x["range"],
            x["ipset"],
            x["entry"],
        )
    )

    print()
    print(
        f"{'BOT / GRUPO':<18} "
        f"{'RANGO BOT':<28} "
        f"{'IPSET':<45} "
        f"{'ENTRADA IPSET'}"
    )

    print("-" * 140)

    for match in matches:

        print(
            f"{match['bot']:<18} "
            f"{match['range']:<28} "
            f"{match['ipset']:<45} "
            f"{match['entry']}"
        )

    print()
    print(
        f"Total de coincidencias: "
        f"{len(matches)}"
    )


def manual_ranges():
    print()
    print(
        "Ingresa una o varias "
        "IPs/rangos IPv4."
    )
    print()
    print("Ejemplos:")
    print("  66.249.66.203")
    print("  66.249.64.0/19")
    print(
        "  40.77.167.0/24, "
        "52.167.144.0/24"
    )
    print()

    raw = input(
        "IPs/Rangos: "
    ).strip()

    raw = raw.replace(",", " ")

    networks = []

    for value in raw.split():

        if ":" in value:
            print(
                f"[AVISO] IPv6 ignorada: "
                f"{value}"
            )
            continue

        try:

            if "/" in value:

                network = ipaddress.ip_network(
                    value,
                    strict=False
                )

            else:

                address = ipaddress.ip_address(
                    value
                )

                if address.version != 4:
                    continue

                network = ipaddress.ip_network(
                    f"{value}/32",
                    strict=False
                )

            if network.version == 4:
                networks.append(network)

        except ValueError:

            print(
                f"[AVISO] Valor inválido "
                f"ignorado: {value}"
            )

    return networks


def show_loaded_ranges(
    search_groups
):
    print()

    for name, ranges in search_groups.items():

        print(
            f"{name}: "
            f"{len(ranges)} rangos IPv4"
        )


def main():
    print()
    print(
        "=============================================="
    )
    print(
        "   Buscador de rangos IPv4 de bots en IPSET"
    )
    print(
        "=============================================="
    )
    print()

    bots = list(
        SOURCES.keys()
    )

    for index, bot in enumerate(
        bots,
        start=1
    ):
        print(
            f"{index}) {bot}"
        )

    option_all = len(bots) + 1
    option_manual = len(bots) + 2

    print(
        f"{option_all}) "
        "Todos los bots"
    )

    print(
        f"{option_manual}) "
        "Introducir IPs/rangos manualmente"
    )

    print()

    try:
        option = int(
            input(
                "Selecciona una opción: "
            )
        )

    except ValueError:
        print(
            "Opción inválida."
        )
        return

    search_groups = {}

    if 1 <= option <= len(bots):

        bot = bots[
            option - 1
        ]

        print()
        print(
            f"Cargando rangos IPv4 "
            f"de {bot}..."
        )

        ranges = load_bot_ranges(
            bot
        )

        if not ranges:
            print(
                "No se obtuvieron "
                "rangos IPv4."
            )
            return

        search_groups[bot] = ranges

    elif option == option_all:

        print()
        print(
            "Cargando rangos IPv4 "
            "de todos los bots..."
        )

        for bot in bots:

            ranges = load_bot_ranges(
                bot
            )

            if ranges:

                search_groups[bot] = ranges

            else:

                print(
                    f"[AVISO] {bot}: "
                    "no se obtuvieron "
                    "rangos IPv4"
                )

    elif option == option_manual:

        ranges = manual_ranges()

        if not ranges:

            print(
                "No se proporcionaron "
                "rangos IPv4 válidos."
            )

            return

        search_groups["Manual"] = ranges

    else:

        print(
            "Opción inválida."
        )
        return

    show_loaded_ranges(
        search_groups
    )

    print()
    print(
        "Leyendo IPSET..."
    )

    ipset_entries = get_ipsets()

    print(
        f"Entradas IPv4 analizables: "
        f"{len(ipset_entries):,}"
    )

    print(
        "IPSET excluido: "
        "i360.ipv4.whitelist.static"
    )

    if not ipset_entries:

        print(
            "No se encontraron "
            "entradas IPv4 analizables."
        )
        return

    print()
    print(
        "Construyendo índices..."
    )

    print(
        "Buscando coincidencias..."
    )

    matches = search_ranges(
        search_groups,
        ipset_entries
    )

    print_results(
        matches
    )


if __name__ == "__main__":
    main()
