import subprocess
import urllib.request
import json
import ipaddress
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
            "2607:6bc0::/48",
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

        # hash:ip,port / hash:net,port
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


def search_ranges(search_groups, ipset_entries):
    matches = []

    for group_name, ranges in search_groups.items():

        for official_range in ranges:

            for item in ipset_entries:

                candidate = item["network"]

                if candidate.version != official_range.version:
                    continue

                if candidate.overlaps(official_range):

                    matches.append({
                        "bot": group_name,
                        "range": str(official_range),
                        "ipset": item["ipset"],
                        "entry": item["entry_raw"],
                    })

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
        f"{'RANGO BUSCADO':<28} "
        f"{'IPSET':<40} "
        f"{'ENTRADA IPSET'}"
    )

    print("-" * 125)

    for match in matches:
        print(
            f"{match['bot']:<18} "
            f"{match['range']:<28} "
            f"{match['ipset']:<40} "
            f"{match['entry']}"
        )

    print()
    print(f"Total de coincidencias: {len(matches)}")


def manual_ranges():
    print()
    print("Ingresa IPs o rangos CIDR.")
    print("Puedes escribir varios separados por espacio o coma.")
    print()
    print("Ejemplos:")
    print("  66.249.66.203")
    print("  66.249.64.0/19")
    print("  40.77.167.0/24, 52.167.144.0/24")
    print()

    raw = input("IPs/Rangos: ").strip()

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
                address = ipaddress.ip_address(value)

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
            print(f"[AVISO] Valor inválido ignorado: {value}")

    return networks


def main():
    print()
    print("==============================================")
    print("   Buscador de rangos de bots en IPSET")
    print("==============================================")
    print()

    bots = list(SOURCES.keys())

    for index, bot in enumerate(bots, start=1):
        print(f"{index}) {bot}")

    print(f"{len(bots) + 1}) Todos los bots")
    print(f"{len(bots) + 2}) Introducir IPs/rangos manualmente")

    print()

    try:
        option = int(input("Selecciona una opción: "))
    except ValueError:
        print("Opción inválida.")
        return

    search_groups = {}

    if 1 <= option <= len(bots):

        bot = bots[option - 1]

        print()
        print(f"Cargando rangos de {bot}...")

        ranges = load_bot_ranges(bot)

        if not ranges:
            print("No se obtuvieron rangos.")
            return

        search_groups[bot] = ranges

        print(f"Rangos cargados: {len(ranges)}")

    elif option == len(bots) + 1:

        print()
        print("Cargando rangos de todos los bots...")

        for bot in bots:

            ranges = load_bot_ranges(bot)

            if ranges:
                search_groups[bot] = ranges
                print(
                    f"{bot}: {len(ranges)} rangos cargados"
                )
            else:
                print(
                    f"{bot}: no se pudieron obtener rangos"
                )

    elif option == len(bots) + 2:

        ranges = manual_ranges()

        if not ranges:
            print("No se proporcionaron rangos válidos.")
            return

        search_groups["Manual"] = ranges

    else:
        print("Opción inválida.")
        return

    print()
    print("Leyendo IPSET...")

    ipset_entries = get_ipsets()

    print(
        f"Entradas IPSET analizables: "
        f"{len(ipset_entries)}"
    )

    print()
    print("Buscando coincidencias...")

    matches = search_ranges(
        search_groups,
        ipset_entries
    )

    print_results(matches)


if __name__ == "__main__":
    main()
