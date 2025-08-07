#!/bin/bash

hosts=(
"svgt264 198.59.144.25"
"svgt269 65.99.225.140"
"svgt270 65.99.252.142"
"svgt271 65.99.252.56"
"svgt272 174.136.25.166"
"svgt279 65.99.225.206"
"svgt283 65.99.225.134"
"svgt285 65.99.225.56"
"svgt286 174.136.25.26"
"svgt287 65.99.225.136"
"svgt302 174.136.53.219"
"svgt303 174.136.53.220"
"svgt313 198.59.144.126"
"svgt314 198.59.144.127"
"svgt326 198.59.144.139"
"svgt327 198.59.144.140"
"svgt328 198.59.144.141"
"svgt332 65.99.252.179"
"svgt333 65.99.252.27"
"svgt334 65.99.252.41"
"svgt385 198.59.144.35"
"svgt393 198.59.144.178"
"svgt394 198.59.144.179"
"svgt395 198.59.144.180"
"svgt396 198.59.144.181"
"svgt397 198.59.144.182"
"svgt424 198.59.144.249"
)

echo -e "\n📡 Escaneando servidores por telnet en puerto 3306...\n"

for entry in "${hosts[@]}"; do
    hostname=$(echo "$entry" | awk '{print $1}')
    ip=$(echo "$entry" | awk '{print $2}')

    # Usamos telnet con timeout y cortamos la salida
    banner=$( (echo quit; sleep 1) | timeout 6 telnet "$ip" 3306 2>/dev/null | head -n 5)

    if [[ $? -eq 0 && -n "$banner" ]]; then
        version=$(echo "$banner" | grep -oEi 'MariaDB[^ ]*|MySQL[^ ]*' | head -1)
        if [[ -n "$version" ]]; then
            echo "[+] $hostname ($ip) -> $version"
        else
            echo "[?] $hostname ($ip) -> Connected, no version found"
        fi
    else
        echo "[-] $hostname ($ip) -> No response on port 3306"
    fi
done
