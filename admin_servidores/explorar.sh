#!/bin/bash

# Número de niveles a explorar
MAX_LEVELS=10

# Comienza en la raíz
CURRENT_DIR="/"

for ((i=1; i<=MAX_LEVELS; i++)); do
    echo "🔎 Nivel $i:"
    echo "📂 Explorando en: $CURRENT_DIR"
    echo "-----------------------------------"
    
    # Muestra las 10 carpetas más grandes con sus tamaños
    du -h --max-depth=1 "$CURRENT_DIR" 2>/dev/null | sort -hr | head -n 10
    
    # Encuentra el primer subdirectorio más grande que no sea el actual
    NEXT_DIR=$(du -h --max-depth=1 "$CURRENT_DIR" 2>/dev/null | sort -hr | awk -v current="$CURRENT_DIR" '$2 != current {print $2}' | head -n 1)
    
    # Si no se encontró ningún directorio, salir
    if [ -z "$NEXT_DIR" ]; then
        echo "⚠️  No se encontró ningún directorio en este nivel."
        break
    fi
    
    # Avanza al siguiente directorio
    CURRENT_DIR="$NEXT_DIR"
    echo
done

echo "🏁 Exploración completa."
