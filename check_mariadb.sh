#!/bin/bash

# Lista de IPs y hostnames
hosts=(
"svgt154 65.99.252.19"
"svgt160 65.99.252.172"
"svgt183 72.249.55.24"
"svgt186 174.136.25.9"
"svgt187 174.136.28.105"
"svgt191 72.249.55.19"
"svgt192 174.136.38.38"
"svgt193 174.136.52.203"
"svgt197 174.136.37.107"
"svgt198 174.136.37.108"
"svgt199 174.136.37.109"
"svgt207 65.99.225.31"
"svgt208 65.99.225.37"
"svgt209 65.99.225.41"
"svgt210 65.99.225.55"
"svgt222 174.136.25.23"
"svgt223 174.136.25.35"
"svgt224 65.99.225.81"
"svgt226 207.210.229.118"
"svgt227 174.136.38.17"
"svgt235 207.210.229.91"
"svgt236 207.210.228.67"
"svgt237 207.210.229.84"
"svgt243 198.59.144.5"
"svgt244 198.59.144.6"
"svgt245 198.59.144.7"
"svgt246 198.59.144.8"
"svgt253 198.59.144.15"
"svgt254 198.59.144.16"
"svgt255 198.59.144.17"
"svgt256 198.59.144.18"
"svgt257 198.59.144.19"
"svgt263 65.99.225.24"
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

echo -e "\nScanning MySQL (port 3306) for MariaDB/MySQL version...\n"

for entry in "${hosts[@]}"; do
    hostname=$(echo "$entry" | awk '{print $1}')
    ip=$(echo "$entry" | awk '{print $2}')

    # Conexión con timeout
    banner=$(timeout 5 bash -c "echo | nc $ip 3306" 2>/dev/null)

    if [[ $? -eq 0 && -n "$banner" ]]; then
        version=$(echo "$banner" | grep -oEi 'MariaDB[^ ]*|MySQL[^ ]*' | head -1)
        if [[ -n "$version" ]]; then
            echo "[+] $hostname ($ip) -> $version"
        else
            echo "[?] $hostname ($ip) -> Connected, but version not found"
        fi
    else
        echo "[-] $hostname ($ip) -> No response on port 3306"
    fi
done
