#!/bin/bash

# ============================================================
# DIAGNOSTICO GENERICO PHP-FPM PARA CPANEL / EASYAPACHE 4
# Solo lectura. No modifica configuracion ni reinicia servicios.
# ============================================================

MINUTES="${1:-30}"
CURL_REPEATS="${2:-3}"

echo
echo "============================================================"
echo " DIAGNOSTICO PHP-FPM CPANEL"
echo " Fecha: $(date)"
echo " Ventana de trafico: ultimos $MINUTES minutos"
echo "============================================================"

echo
echo "============================================================"
echo "1. RECURSOS DEL VPS"
echo "============================================================"
echo

echo "--- MEMORIA ---"
free -m

echo
echo "--- CPU ---"
echo "Nucleos: $(nproc)"
lscpu 2>/dev/null | grep -E '^Model name:|^CPU\(s\):' | head -2

echo
echo "--- CARGA ---"
uptime

echo
echo "--- SWAP ---"
swapon --show 2>/dev/null || true

echo
echo "============================================================"
echo "2. VERSIONES PHP-FPM INSTALADAS"
echo "============================================================"
echo

for dir in /opt/cpanel/ea-php*/root/etc/php-fpm.d; do
    [ -d "$dir" ] || continue

    phpver=$(echo "$dir" | sed -n 's#^/opt/cpanel/\(ea-php[0-9]*\)/.*#\1#p')

    printf "%-12s pools=%s\n" \
        "$phpver" \
        "$(find "$dir" -maxdepth 1 -name '*.conf' -type f | wc -l)"
done

echo
echo "============================================================"
echo "3. CONFIGURACION ACTUAL DE TODOS LOS POOLS"
echo "============================================================"
echo

printf "%-10s %-42s %-10s %-10s %-10s %-8s\n" \
    "PHP" "POOL" "MODE" "CHILDREN" "REQUESTS" "IDLE"

for f in /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf; do

    [ -f "$f" ] || continue

    phpver=$(echo "$f" | sed -n 's#^/opt/cpanel/\(ea-php[0-9]*\)/.*#\1#p')
    pool=$(basename "$f" .conf)

    pm=$(awk -F= '
        /^[[:space:]]*pm[[:space:]]*=/ {
            gsub(/[[:space:]]/,"",$2)
            print $2
            exit
        }' "$f")

    children=$(awk -F= '
        /^[[:space:]]*pm\.max_children[[:space:]]*=/ {
            gsub(/[[:space:]]/,"",$2)
            print $2
            exit
        }' "$f")

    requests=$(awk -F= '
        /^[[:space:]]*pm\.max_requests[[:space:]]*=/ {
            gsub(/[[:space:]]/,"",$2)
            print $2
            exit
        }' "$f")

    idle=$(awk -F= '
        /^[[:space:]]*pm\.process_idle_timeout[[:space:]]*=/ {
            gsub(/[[:space:]]/,"",$2)
            print $2
            exit
        }' "$f")

    printf "%-10s %-42s %-10s %-10s %-10s %-8s\n" \
        "$phpver" "$pool" "${pm:--}" "${children:--}" \
        "${requests:--}" "${idle:--}"

done | sort

echo
echo "============================================================"
echo "4. MEMORIA ACTUAL POR POOL PHP-FPM"
echo "============================================================"
echo

ps -eo rss,args |
awk '
/php-fpm: pool/ {

    rss=$1/1024

    for(i=2;i<=NF;i++) {

        if($i=="pool") {

            pool=$(i+1)
            gsub(/[()]/,"",pool)

            count[pool]++
            total[pool]+=rss

            if(rss > max[pool])
                max[pool]=rss

            if(min[pool]==0 || rss < min[pool])
                min[pool]=rss
        }
    }
}
END {

    printf "%-42s %8s %11s %11s %11s %11s\n",
           "POOL","WORKERS","TOTAL_MB","AVG_MB","MIN_MB","MAX_MB"

    for(pool in count) {

        printf "%-42s %8d %11.1f %11.1f %11.1f %11.1f\n",
               pool,
               count[pool],
               total[pool],
               total[pool]/count[pool],
               min[pool],
               max[pool]
    }
}' | sort

echo
echo "============================================================"
echo "5. RESUMEN GLOBAL DE MEMORIA PHP"
echo "============================================================"
echo

ps -eo rss,args |
awk '
/php-fpm: pool/ {
    workers++
    mem += $1
}
/php-cgi/ && !/awk/ {
    cgi++
    cgimem += $1
}
END {
    printf "PHP-FPM workers activos : %d\n",workers
    printf "RAM PHP-FPM total       : %.1f MB\n",mem/1024
    printf "PHP-CGI activos         : %d\n",cgi
    printf "RAM PHP-CGI total       : %.1f MB\n",cgimem/1024
}'

echo
echo "============================================================"
echo "6. POOLS QUE HAN ALCANZADO MAX_CHILDREN"
echo "============================================================"
echo

FOUND=0

for log in \
    /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log \
    /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/*.log \
    /var/log/php-fpm* \
    /var/log/php-fpm/*

do
    [ -f "$log" ] || continue

    hits=$(grep -iE \
        'server reached pm.max_children|max_children.*reached|seems busy' \
        "$log" 2>/dev/null | tail -30)

    if [ -n "$hits" ]; then
        echo "--- $log ---"
        echo "$hits"
        FOUND=1
    fi
done

[ "$FOUND" -eq 0 ] && echo "No se encontraron eventos de max_children en los logs revisados."

echo
echo "============================================================"
echo "7. CREANDO VENTANA TEMPORAL DE $MINUTES MINUTOS"
echo "============================================================"

PAT=$(mktemp)

for i in $(seq 0 $((MINUTES-1))); do
    date -d "$i minutes ago" '+[%d/%b/%Y:%H:%M:' >> "$PAT"
done

echo "OK"

echo
echo "============================================================"
echo "8. TRAFICO RECIENTE POR DOMINIO"
echo "============================================================"
echo

analyze_log()
{
    local logfile="$1"
    local domain="$2"

    TMP=$(mktemp)

    grep -Ff "$PAT" "$logfile" 2>/dev/null > "$TMP"

    total=$(wc -l < "$TMP")

    if [ "$total" -eq 0 ]; then
        rm -f "$TMP"
        return
    fi

    dynamic=$(awk -F'"' '
    {
        split($2,a," ")
        url=a[2]

        if (url ~ /\.php/ ||
            url ~ /\/$/ ||
            url !~ /\.(css|js|jpg|jpeg|png|gif|webp|svg|ico|woff|woff2|ttf|map|mp4|webm|pdf|zip|xml|txt)(\?|$)/)
            n++
    }
    END {
        print n+0
    }' "$TMP")

    peak=$(awk '
    {
        if (match($0,/\[[0-9][0-9]\/[A-Za-z]+\/[0-9]+:[0-9][0-9]:[0-9][0-9]:/)) {
            ts=substr($0,RSTART+1,RLENGTH-2)
            sub(/:[0-9][0-9]:$/,":",ts)
            hits[ts]++
        }
    }
    END {
        max=0
        for(x in hits)
            if(hits[x]>max)
                max=hits[x]

        print max+0
    }' "$TMP")

    errors=$(awk '
    {
        if(match($0,/" [45][0-9][0-9] /))
            n++
    }
    END {print n+0}' "$TMP")

    printf "%-45s total=%-7s dynamic=%-7s peak/min=%-6s 4xx5xx=%s\n" \
        "$domain" "$total" "$dynamic" "$peak" "$errors"

    rm -f "$TMP"
}

if [ -d /var/log/nginx/domains ]; then

    echo "Fuente: Nginx"
    echo

    for f in /var/log/nginx/domains/*; do

        [ -f "$f" ] || continue

        case "$f" in
            *-bytes_log|*.gz|*.bk|*.bak|*-error.log|*_error.log)
                continue
                ;;
        esac

        domain=$(basename "$f")

        # Evita contabilizar dos veces variantes SSL si existen como
        # archivos independientes.
        case "$domain" in
            *-ssl_log)
                continue
                ;;
        esac

        analyze_log "$f" "$domain"

    done | sort -k2 -nr

else

    echo "Nginx no detectado. Fuente: Apache domlogs"
    echo

    for f in /etc/apache2/logs/domlogs/*; do

        [ -f "$f" ] || continue

        domain=$(basename "$f")

        case "$domain" in
            *-bytes_log|*-ssl_log|*.gz|*.bk|*.bak)
                continue
                ;;
        esac

        analyze_log "$f" "$domain"

    done | sort -k2 -nr

fi

echo
echo "============================================================"
echo "9. DOMINIOS CON POOL FPM DETECTADOS"
echo "============================================================"
echo

DOMAIN_FILE=$(mktemp)

for f in /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf; do

    [ -f "$f" ] || continue

    domain=$(basename "$f" .conf)

    # Solo nombres que parecen FQDN reales.
    if echo "$domain" | grep -qE '^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$'; then
        echo "$domain"
    fi

done | sort -u > "$DOMAIN_FILE"

cat "$DOMAIN_FILE"

echo
echo "============================================================"
echo "10. TIEMPOS HTTP DE DOMINIOS CON PHP-FPM"
echo "============================================================"
echo

while read -r domain; do

    [ -n "$domain" ] || continue

    echo "--- $domain ---"

    for n in $(seq 1 "$CURL_REPEATS"); do

        curl -kLsS \
            --connect-timeout 5 \
            --max-time 20 \
            -o /dev/null \
            -w "HTTP=%{http_code} TTFB=%{time_starttransfer}s TOTAL=%{time_total}s SIZE=%{size_download}\n" \
            "https://$domain/" 2>/dev/null ||
        echo "ERROR/TIMEOUT"

    done

done < "$DOMAIN_FILE"

echo
echo "============================================================"
echo "11. PROCESOS PHP ACTIVOS"
echo "============================================================"
echo

ps -eo user,pid,state,rss,etime,args --sort=-rss |
grep -E 'php-fpm: pool|php-cgi' |
grep -v grep |
head -150

echo
echo "============================================================"
echo "12. TOP PROCESOS DEL VPS POR RAM"
echo "============================================================"
echo

ps -eo user,pid,state,%mem,rss,etime,args --sort=-rss |
head -25

echo
echo "============================================================"
echo "13. RESUMEN PARA CALCULAR MAX_CHILDREN"
echo "============================================================"
echo

echo "Formula orientativa:"
echo
echo "  max_children_pool ~= RAM_asignable_al_pool / RAM_promedio_por_worker"
echo
echo "Capacidad PHP aproximada:"
echo
echo "  requests/min ~= max_children * 60 / tiempo_promedio_peticion"
echo
echo "IMPORTANTE:"
echo "  - No usar toda la RAM disponible para PHP."
echo "  - Reservar memoria para MariaDB, Apache/Nginx, cPanel,"
echo "    Exim, Dovecot, sistema operativo y cache."
echo "  - La swap es proteccion de emergencia, no RAM util para"
echo "    dimensionar workers sostenidos."
echo "  - max_requests NO limita trafico ni concurrencia."
echo "    Solo recicla cada worker despues de N peticiones."
echo

rm -f "$PAT" "$DOMAIN_FILE"

echo "============================================================"
echo " FIN DEL DIAGNOSTICO"
echo "============================================================"
