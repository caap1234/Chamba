#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import subprocess
import json
import sys
import os
import socket
import struct
import bisect
from datetime import datetime

try:
    input_func = raw_input
except NameError:
    input_func = input


EXCLUDED_IPSETS = set([
    "i360.ipv4.whitelist.static",
])


SOURCES = {
    "Googlebot": {
        "type": "json",
        "url": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    },

    "FacebookMeta": {
        "type": "static",
        "ranges": [
            "31.13.24.0/21",
            "31.13.64.0/18",
            "45.64.40.0/22",
            "57.144.0.0/14",
            "66.220.144.0/20",
            "69.63.176.0/20",
            "69.171.224.0/19",
            "74.119.76.0/22",
            "102.132.96.0/20",
            "103.4.96.0/22",
            "129.134.0.0/17",
            "157.240.0.0/17",
            "157.240.192.0/18",
            "163.70.128.0/17",
            "173.252.64.0/18",
            "179.60.192.0/22",
            "185.60.216.0/22",
            "185.89.216.0/22",
            "204.15.20.0/22",
        ],
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

    "LGEPartner": {
        "type": "static",
        "ranges": [
            "156.147.1.0/24",
            "156.147.51.0/24",
            "156.147.23.0/24",
            "204.79.148.137",
            "204.79.148.138",
            "136.166.1.5",
            "136.166.200.192",
            "136.166.200.193",
            "10.185.218.104",
            "10.185.218.105",
            "203.247.149.204",
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


def ipv4_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except socket.error:
        raise ValueError("IPv4 invalida")


def int_to_ipv4(value):
    return socket.inet_ntoa(struct.pack("!I", value))


def parse_network(value):
    value = value.strip()

    if ":" in value:
        raise ValueError("IPv6 no soportada")

    if "/" in value:
        ip, prefix = value.split("/", 1)

        try:
            prefix = int(prefix)
        except ValueError:
            raise ValueError("Prefijo invalido")

        if prefix < 0 or prefix > 32:
            raise ValueError("Prefijo invalido")

    else:
        ip = value
        prefix = 32

    ip_int = ipv4_to_int(ip)

    if prefix == 0:
        mask = 0
    else:
        mask = (0xffffffff << (32 - prefix)) & 0xffffffff

    network_start = ip_int & mask
    network_end = network_start | (0xffffffff ^ mask)

    cidr = "%s/%d" % (
        int_to_ipv4(network_start),
        prefix
    )

    return {
        "start": network_start,
        "end": network_end,
        "cidr": cidr,
    }


def run_command(args):
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        raise RuntimeError(
            stderr.decode(
                "utf-8",
                "ignore"
            )
        )

    if not isinstance(stdout, str):
        stdout = stdout.decode(
            "utf-8",
            "ignore"
        )

    return stdout


def download(url):
    return run_command([
        "wget",
        "-qO-",
        url
    ])


def download_json(url):
    data = download(url)
    return json.loads(data)


def load_bot_ranges(bot_name):
    source = SOURCES[bot_name]
    ranges = []

    if source["type"] == "static":

        for cidr in source["ranges"]:
            try:
                network = parse_network(cidr)
                ranges.append(network)
            except ValueError:
                pass

        return ranges

    if source["type"] == "text":

        try:
            data = download(
                source["url"]
            )

        except Exception as e:
            print(
                "[ERROR] No se pudo obtener %s: %s"
                % (bot_name, e)
            )
            return []

        for cidr in data.splitlines():

            cidr = cidr.strip()

            if not cidr:
                continue

            try:
                ranges.append(
                    parse_network(cidr)
                )
            except ValueError:
                pass

        return ranges

    try:
        data = download_json(
            source["url"]
        )

    except Exception as e:
        print(
            "[ERROR] No se pudo obtener %s: %s"
            % (bot_name, e)
        )
        return []

    for prefix in data.get(
        "prefixes",
        []
    ):

        cidr = prefix.get(
            "ipv4Prefix"
        )

        if not cidr:
            continue

        try:
            ranges.append(
                parse_network(cidr)
            )
        except ValueError:
            pass

    return ranges


def get_ipsets():

    try:
        output = run_command([
            "ipset",
            "save"
        ])

    except Exception as e:

        print(
            "[ERROR] No se pudo ejecutar ipset save: %s"
            % e
        )

        sys.exit(1)

    entries = []

    for line in output.splitlines():

        if not line.startswith(
            "add "
        ):
            continue

        parts = line.split()

        if len(parts) < 3:
            continue

        ipset_name = parts[1]

        if ipset_name in EXCLUDED_IPSETS:
            continue

        entry_raw = parts[2]

        # Ejemplos soportados:
        # 1.2.3.4
        # 1.2.3.0/24
        # 1.2.3.4,tcp:80
        # 1.2.3.0/24,tcp:443

        entry = entry_raw.split(",")[0]

        if ":" in entry:
            continue

        try:
            network = parse_network(
                entry
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

    for bot in search_groups:

        ranges = search_groups[bot]

        intervals = []

        for network in ranges:

            intervals.append(
                (
                    network["start"],
                    network["end"],
                    network["cidr"]
                )
            )

        intervals.sort(
            key=lambda x: x[0]
        )

        starts = []

        for item in intervals:
            starts.append(
                item[0]
            )

        indexes[bot] = {
            "intervals": intervals,
            "starts": starts,
        }

    return indexes


def find_overlap(candidate, index):

    intervals = index["intervals"]
    starts = index["starts"]

    if not intervals:
        return None

    candidate_start = candidate[
        "start"
    ]

    candidate_end = candidate[
        "end"
    ]

    pos = bisect.bisect_right(
        starts,
        candidate_end
    )

    i = pos - 1

    while i >= 0:

        start = intervals[i][0]
        end = intervals[i][1]
        cidr = intervals[i][2]

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

    total = len(
        ipset_entries
    )

    counter = 0

    for item in ipset_entries:

        counter += 1

        candidate = item[
            "network"
        ]

        for bot in indexes:

            official_range = find_overlap(
                candidate,
                indexes[bot]
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
                "  Procesadas %d / %d entradas..."
                % (
                    counter,
                    total
                )
            )

    return matches


def sort_matches(matches):

    return sorted(
        matches,
        key=lambda x: (
            x["bot"],
            x["range"],
            x["ipset"],
            x["entry"]
        )
    )


def print_results(matches):

    if not matches:
        print("")
        print(
            "No se encontraron coincidencias."
        )
        return

    matches = sort_matches(
        matches
    )

    print("")

    print(
        "%-18s %-28s %-45s %s"
        % (
            "BOT / GRUPO",
            "RANGO BOT",
            "IPSET",
            "ENTRADA IPSET"
        )
    )

    print("-" * 140)

    for match in matches:

        print(
            "%-18s %-28s %-45s %s"
            % (
                match["bot"],
                match["range"],
                match["ipset"],
                match["entry"]
            )
        )

    print("")

    print(
        "Total de coincidencias: %d"
        % len(matches)
    )


def export_results_txt(matches):

    if not matches:
        return None, None

    output_dir = "/var/www/html"

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = (
        "coincidencias_ipset_%s.txt"
        % timestamp
    )

    filepath = os.path.join(
        output_dir,
        filename
    )

    matches = sort_matches(
        matches
    )

    lines = []

    lines.append(
        "%-18s %-28s %-45s %s"
        % (
            "BOT / GRUPO",
            "RANGO BOT",
            "IPSET",
            "ENTRADA IPSET"
        )
    )

    lines.append(
        "-" * 140
    )

    for match in matches:

        lines.append(
            "%-18s %-28s %-45s %s"
            % (
                match["bot"],
                match["range"],
                match["ipset"],
                match["entry"]
            )
        )

    lines.append("")

    lines.append(
        "Total de coincidencias: %d"
        % len(matches)
    )

    lines.append("")

    try:

        if not os.path.isdir(
            output_dir
        ):
            os.makedirs(
                output_dir
            )

        f = open(
            filepath,
            "w"
        )

        f.write(
            "\n".join(lines)
        )

        f.close()

        os.chmod(
            filepath,
            0644
        )

    except Exception as e:

        print("")
        print(
            "[ERROR] No se pudo exportar TXT: %s"
            % e
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
            (
                "http://",
                "https://"
            )
        )
    ):

        url = "http://%s/%s" % (
            http_host,
            filename
        )

    elif http_host:

        url = "%s/%s" % (
            http_host.rstrip("/"),
            filename
        )

    else:

        url = (
            "http://IP_DEL_SERVIDOR/%s"
            % filename
        )

    return filepath, url


def manual_ranges():

    print("")
    print(
        "Ingresa una o varias IPs/rangos IPv4."
    )

    print("")
    print("Ejemplos:")
    print("  66.249.66.203")
    print("  66.249.64.0/19")
    print(
        "  40.77.167.0/24, 52.167.144.0/24"
    )
    print("")

    raw = input_func(
        "IPs/Rangos: "
    ).strip()

    raw = raw.replace(
        ",",
        " "
    )

    networks = []

    for value in raw.split():

        if ":" in value:

            print(
                "[AVISO] IPv6 ignorada: %s"
                % value
            )

            continue

        try:

            network = parse_network(
                value
            )

            networks.append(
                network
            )

        except ValueError:

            print(
                "[AVISO] Valor invalido ignorado: %s"
                % value
            )

    return networks


def show_loaded_ranges(
    search_groups
):

    print("")

    for name in search_groups:

        print(
            "%s: %d rangos IPv4"
            % (
                name,
                len(
                    search_groups[name]
                )
            )
        )


def main():

    print("")
    print(
        "=============================================="
    )
    print(
        "   Buscador de rangos IPv4 de bots en IPSET"
    )
    print(
        "=============================================="
    )
    print("")

    bots = list(
        SOURCES.keys()
    )

    bots.sort()

    index = 1

    for bot in bots:

        print(
            "%d) %s"
            % (
                index,
                bot
            )
        )

        index += 1

    option_all = len(
        bots
    ) + 1

    option_manual = len(
        bots
    ) + 2

    print(
        "%d) Todos los bots"
        % option_all
    )

    print(
        "%d) Introducir IPs/rangos manualmente"
        % option_manual
    )

    print("")

    try:

        option = int(
            input_func(
                "Selecciona una opcion: "
            )
        )

    except ValueError:

        print(
            "Opcion invalida."
        )

        return

    search_groups = {}

    if (
        option >= 1
        and option <= len(bots)
    ):

        bot = bots[
            option - 1
        ]

        print("")
        print(
            "Cargando rangos IPv4 de %s..."
            % bot
        )

        ranges = load_bot_ranges(
            bot
        )

        if not ranges:

            print(
                "No se obtuvieron rangos IPv4."
            )

            return

        search_groups[bot] = ranges

    elif option == option_all:

        print("")
        print(
            "Cargando rangos IPv4 de todos los bots..."
        )

        for bot in ALL_BOTS:

            ranges = load_bot_ranges(
                bot
            )

            if ranges:

                search_groups[
                    bot
                ] = ranges

            else:

                print(
                    "[AVISO] %s: no se obtuvieron rangos IPv4"
                    % bot
                )

    elif option == option_manual:

        ranges = manual_ranges()

        if not ranges:

            print(
                "No se proporcionaron rangos IPv4 validos."
            )

            return

        search_groups[
            "Manual"
        ] = ranges

    else:

        print(
            "Opcion invalida."
        )

        return

    show_loaded_ranges(
        search_groups
    )

    print("")
    print(
        "Leyendo IPSET..."
    )

    ipset_entries = get_ipsets()

    print(
        "Entradas IPv4 analizables: %d"
        % len(ipset_entries)
    )

    print(
        "IPSET excluido: i360.ipv4.whitelist.static"
    )

    if not ipset_entries:

        print(
            "No se encontraron entradas IPv4 analizables."
        )

        return

    print("")
    print(
        "Construyendo indices..."
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

    if matches:

        filepath, url = export_results_txt(
            matches
        )

        if filepath:

            print("")
            print(
                "Resultados exportados a: %s"
                % filepath
            )

            print(
                "Permisos aplicados: 644"
            )

            print(
                "Enlace de descarga: %s"
                % url
            )


if __name__ == "__main__":
    main()
