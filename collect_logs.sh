import subprocess
import urllib.request
import json
import ipaddress
import bisect
import sys


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
            "2607:6bc0::/48",
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
                ranges.append(
                    ipaddress.ip_network(cidr, strict=False)
                )
            except ValueError:
                pass

        return ranges

    try:
        data = download_json(source["url"])

    except Exception as e:
        print(f"[ERROR] No se pudo obtener {bot_name}: {e}")
        return []

    for prefix in data.get("prefixes", []):
        cidr = (
            prefix.get("ipv4Prefix")
            or prefix.get("ipv6Prefix")
        )

        if not cidr:
            continue

        try:
            ranges.append(
                ipaddress.ip_network(cidr, strict=False)
            )
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
        print(f"[ERROR] No se pudo ejecutar ipset save: {e}")
        sys.exit(1)

    entries = []

    for line in output.splitlines():
        if not line.startswith("add "):
            continue

        parts = line.split()

        if len(parts) < 3:
            continue

        ipset_name = parts[1]
        entry_raw = parts[2]

        # Soporta:
        # 1.2.3.4
        # 1.2.3.0/24
        # 1.2.3.4,tcp:80
        # 1.2.3.0/24,tcp:443
        entry = entry_raw.split(",")[0]

        try:
            if "/" in entry:
                network = ipaddress.ip_network(
                    entry,
                    strict=False
                )

            else:
                address = ipaddress.ip_address(entry)

                prefix = (
                    32
                    if address.version == 4
                    else 128
                )

                network = ipaddress.ip_network(
                    f"{entry}/{prefix}",
                    strict=False
                )

        except ValueError:
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

        indexes[bot] = {}

        for version in (4, 6):

            intervals = []

            for network in ranges:

                if network.version != version:
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

            starts = [
                item[0]
                for item in intervals
            ]

            indexes[bot][version] = {
                "intervals": intervals,
                "starts": starts
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

    # Busca únicamente hasta el último rango cuyo inicio
    # pueda caer antes del final del candidato.
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


def search_ranges(search_groups, ipset_entries):
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

        for bot, versions in indexes.items():

            version_index = versions.get(
                candidate.version
            )

            if not version_index:
                continue

            official_range = find_overlap(
                candidate,
                version_index
            )

            if official_range:

                matches.append({
                    "bot": bot,
                    "range": official_range,
                    "ipset": item["ipset"],
                    "entry": item["entry_raw"],
                })

        # Progreso cada 100,000 entradas
        if counter % 100000 == 0:
            print(
                f"  Procesadas "
                f"{counter:,} / {total:,} entradas..."
            )

    return matches


def print_results(matches):
    if not matches:
        print()
        print("No se encontraron coincidencias.")
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
    print("Ingresa una o varias IPs/rangos CIDR.")
    print()
    print("Ejemplos:")
    print("  66.249.66.203")
    print("  66.249.64.0/19")
    print("  40.77.167.0/24, 52.167.144.0/24")
    print()

    raw = input(
        "IPs/Rangos: "
    ).strip()

    raw = raw.replace(",", " ")

    networks = []

    for value in raw.split():

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

                prefix = (
                    32
                    if address.version == 4
                    else 128
                )

                network = ipaddress.ip_network(
                    f"{value}/{prefix}",
                    strict=False
                )

            networks.append(network)

        except ValueError:

            print(
                f"[AVISO] Valor inválido ignorado: "
                f"{value}"
            )

    return networks


def show_loaded_ranges(search_groups):
    print()

    for name, ranges in search_groups.items():

        ipv4 = sum(
            1 for r in ranges
            if r.version == 4
        )

        ipv6 = sum(
            1 for r in ranges
            if r.version == 6
        )

        print(
            f"{name}: "
            f"{len(ranges)} rangos "
            f"(IPv4: {ipv4}, IPv6: {ipv6})"
        )


def main():
    print()
    print("==============================================")
    print("   Buscador de rangos de bots en IPSET")
    print("==============================================")
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
        f"{option_all}) Todos los bots"
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
        print("Opción inválida.")
        return

    search_groups = {}

    if 1 <= option <= len(bots):

        bot = bots[
            option - 1
        ]

        print()
        print(
            f"Cargando rangos de {bot}..."
        )

        ranges = load_bot_ranges(
            bot
        )

        if not ranges:
            print(
                "No se obtuvieron rangos."
            )
            return

        search_groups[bot] = ranges

    elif option == option_all:

        print()
        print(
            "Cargando rangos de todos los bots..."
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
                    "no se obtuvieron rangos"
                )

    elif option == option_manual:

        ranges = manual_ranges()

        if not ranges:

            print(
                "No se proporcionaron "
                "rangos válidos."
            )

            return

        search_groups["Manual"] = ranges

    else:
        print("Opción inválida.")
        return

    show_loaded_ranges(
        search_groups
    )

    print()
    print("Leyendo IPSET...")

    ipset_entries = get_ipsets()

    print(
        f"Entradas IPSET analizables: "
        f"{len(ipset_entries):,}"
    )

    if not ipset_entries:

        print(
            "No se encontraron "
            "entradas analizables."
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
