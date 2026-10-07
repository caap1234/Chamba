#!/usr/bin/env python3

import subprocess
import urllib.request
import json
import ipaddress
import bisect
import sys
import os
import socket
from datetime import datetime


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

    "Mailgun": {
        "type": "static",
        "ranges": [
            "159.135.224.0/20",
            "69.72.32.0/20",
            "204.220.90.0/23",
            "204.220.92.0/22",
            "161.38.192.0/20",
            "143.55.224.0/21",
            "143.55.232.0/22",
            "159.112.240.0/20",
            "198.244.48.0/20",
            "204.220.168.0/21",
            "204.220.176.0/20",
            "141.193.32.0/23",
            "159.135.140.80/29",
            "159.135.132.128/25",
            "161.38.204.0/22",
            "87.253.232.0/21",
            "185.189.236.0/22",
            "185.211.120.0/22",
            "185.250.236.0/22",
            "143.55.236.0/22",
            "198.244.60.0/22",
            "204.220.160.0/20",
        ],
    },

    "Microsoft365": {
        "type": "static",
        "ranges": [
            "40.92.0.0/15",
            "40.107.0.0/16",
            "52.100.0.0/14",
            "52.238.78.88/32",
            "104.47.0.0/17",
        ],
    },

    "PayPal": {
        "type": "static",
        "ranges": [
            "64.4.240.0/21",
            "64.4.248.0/22",
            "66.211.168.0/22",
            "91.243.72.0/23",
            "173.0.80.0/20",
            "185.177.52.0/22",
            "192.160.215.0/24",
            "198.54.216.0/23",
        ],
    },

    "Brevo": {
        "type": "static",
        "ranges": [
            "1.179.112.0/20",
            "77.32.148.0/24",
            "77.32.149.0/24",
            "77.32.170.0/24",
            "172.246.240.0/20",
            "185.41.28.0/24",
            "212.146.244.0/24",
        ],
    },

    "Cloudflare": {
        "type": "text",
        "url": "https://www.cloudflare.com/ips-v4/",
    },
}


ALL_BOTS = [
    "Googlebot",
    "Bingbot",
    "PerplexityBot",
    "GPTBot",
    "Anthropic",
]


def download_json(url):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0"
        }
    )

    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def download_text(url):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0"
        }
    )

    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read().decode("utf-8")


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

    if source["type"] == "text":
        try:
            data = download_text(source["url"])

        except Exception as e:
            print(
                "[ERROR] No se pudo obtener {}: {}".format(
                    bot_name,
                    e
                )
            )
            return []

        for cidr in data.splitlines():
            cidr = cidr.strip()

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

    try:
        data = download_json(source["url"])

    except Exception as e:
        print(
            "[ERROR] No se pudo obtener {}: {}".format(
                bot_name,
                e
            )
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
            universal_newlines=True,
            stderr=subprocess.DEVNULL
        )

    except FileNotFoundError:
        print(
            "[ERROR] El comando 'ipset' no existe en este servidor."
        )
        print(
            "Verifica si el firewall utiliza ipset, CSF/LFD o Imunify360."
        )
        sys.exit(1)

    except subprocess.CalledProcessError as e:
        print(
            "[ERROR] 'ipset save' terminó con error: {}".format(e)
        )
        sys.exit(1)

    except Exception as e:
        print(
            "[ERROR] No se pudo ejecutar ipset save: {}".format(e)
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

        # Ignorar IPv6
        if ":" in entry:
            continue

        try:

            if "/" in entry:

                network = ipaddress.ip_network(
                    entry,
                    strict=False
                )

            else:

                address = ipaddress.ip_address(entry)

                if address.version != 4:
                    continue

                network = ipaddress.ip_network(
                    "{}/32".format(entry),
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


def search_ranges(search_groups, ipset_entries):
    matches = []

    indexes = build_indexes(search_groups)

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
                "  Procesadas {:,} / {:,} entradas...".format(
                    counter,
                    total
                )
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
        "{:<18} {:<28} {:<45} {}".format(
            "BOT / GRUPO",
            "RANGO BOT",
            "IPSET",
            "ENTRADA IPSET"
        )
    )

    print("-" * 140)

    for match in matches:

        print(
            "{:<18} {:<28} {:<45} {}".format(
                match["bot"],
                match["range"],
                match["ipset"],
                match["entry"]
            )
        )

    print()
    print(
        "Total de coincidencias: {}".format(
            len(matches)
        )
    )


def export_results_txt(matches):
    if not matches:
        return None, None

    output_dir = "/var/www/html"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = "coincidencias_ipset_{}.txt".format(timestamp)
    filepath = os.path.join(output_dir, filename)

    matches_sorted = sorted(
        matches,
        key=lambda x: (
            x["bot"],
            x["range"],
            x["ipset"],
            x["entry"],
        )
    )

    lines = []

    lines.append(
        "{:<18} {:<28} {:<45} {}".format(
            "BOT / GRUPO",
            "RANGO BOT",
            "IPSET",
            "ENTRADA IPSET"
        )
    )

    lines.append("-" * 140)

    for match in matches_sorted:

        lines.append(
            "{:<18} {:<28} {:<45} {}".format(
                match["bot"],
                match["range"],
                match["ipset"],
                match["entry"]
            )
        )

    lines.append("")
    lines.append(
        "Total de coincidencias: {}".format(
            len(matches_sorted)
        )
    )
    lines.append("")

    try:
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        os.chmod(filepath, 0o644)

    except PermissionError:
        print()
        print(
            "[ERROR] Sin permisos para escribir en {}.".format(
                output_dir
            )
        )
        return None, None

    except Exception as e:
        print()
        print(
            "[ERROR] No se pudo exportar el TXT: {}".format(e)
        )
        return None, None

    http_host = os.environ.get(
        "SERVER_HTTP_HOST",
        ""
    ).strip()

    if not http_host:
        try:
            http_host = socket.gethostbyname(
                socket.gethostname()
            )
        except Exception:
            http_host = ""

    if (
        http_host
        and not http_host.startswith(
            ("http://", "https://")
        )
    ):
        url = "http://{}/{}".format(
            http_host,
            filename
        )

    elif http_host:

        url = "{}/{}".format(
            http_host.rstrip("/"),
            filename
        )

    else:

        url = "http://IP_DEL_SERVIDOR/{}".format(
            filename
        )

    return filepath, url


def manual_ranges():
    print()
    print("Ingresa una o varias IPs/rangos IPv4.")
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

        if ":" in value:
            print(
                "[AVISO] IPv6 ignorada: {}".format(
                    value
                )
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
                    "{}/32".format(value),
                    strict=False
                )

            if network.version == 4:
                networks.append(network)

        except ValueError:

            print(
                "[AVISO] Valor inválido ignorado: {}".format(
                    value
                )
            )

    return networks


def show_loaded_ranges(search_groups):
    print()

    for name, ranges in search_groups.items():

        print(
            "{}: {} rangos IPv4".format(
                name,
                len(ranges)
            )
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

    bots = list(SOURCES.keys())

    for index, bot in enumerate(
        bots,
        start=1
    ):
        print(
            "{}) {}".format(
                index,
                bot
            )
        )

    option_all = len(bots) + 1
    option_manual = len(bots) + 2

    print(
        "{}) Todos los bots".format(
            option_all
        )
    )

    print(
        "{}) Introducir IPs/rangos manualmente".format(
            option_manual
        )
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
            "Cargando rangos IPv4 de {}...".format(
                bot
            )
        )

        ranges = load_bot_ranges(bot)

        if not ranges:
            print(
                "No se obtuvieron rangos IPv4."
            )
            return

        search_groups[bot] = ranges

    elif option == option_all:

        print()
        print(
            "Cargando rangos IPv4 de todos los bots..."
        )

        for bot in ALL_BOTS:

            ranges = load_bot_ranges(
                bot
            )

            if ranges:

                search_groups[bot] = ranges

            else:

                print(
                    "[AVISO] {}: no se obtuvieron rangos IPv4".format(
                        bot
                    )
                )

    elif option == option_manual:

        ranges = manual_ranges()

        if not ranges:

            print(
                "No se proporcionaron rangos IPv4 válidos."
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
        "Entradas IPv4 analizables: {:,}".format(
            len(ipset_entries)
        )
    )

    print(
        "IPSET excluido: i360.ipv4.whitelist.static"
    )

    if not ipset_entries:

        print(
            "No se encontraron entradas IPv4 analizables."
        )
        return

    print()
    print("Construyendo índices...")
    print("Buscando coincidencias...")

    matches = search_ranges(
        search_groups,
        ipset_entries
    )

    print_results(
        matches
    )

    if matches:

        filepath, url = export_results_txt(
            matches
        )

        if filepath:

            print()
            print(
                "Resultados exportados a: {}".format(
                    filepath
                )
            )

            print(
                "Permisos aplicados: 644"
            )

            print(
                "Enlace de descarga: {}".format(
                    url
                )
            )


if __name__ == "__main__":
    main()
