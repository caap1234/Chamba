#!/bin/bash

set -e

echo "=== Actualizando sistema ==="
sudo apt update -y
sudo apt upgrade -y

echo "=== Instalando Apache, MariaDB, PHP y dependencias ==="
sudo apt install -y apache2 mariadb-server mariadb-client git unzip curl \
php php-mysql php-gd php-cli php-common php-mbstring php-xml php-curl libapache2-mod-php

echo "=== Iniciando servicios ==="
sudo systemctl enable apache2
sudo systemctl enable mariadb
sudo systemctl start apache2
sudo systemctl start mariadb

echo "=== Descargando DVWA ==="
cd /var/www/html
sudo rm -rf dvwa
sudo git clone https://github.com/digininja/DVWA.git dvwa

echo "=== Configurando permisos ==="
sudo chown -R www-data:www-data /var/www/html/dvwa
sudo chmod -R 755 /var/www/html/dvwa
sudo chmod -R 777 /var/www/html/dvwa/hackable/uploads
sudo chmod -R 777 /var/www/html/dvwa/config

echo "=== Configurando archivo de DVWA ==="
cd /var/www/html/dvwa/config
sudo cp -f config.inc.php.dist config.inc.php

echo "=== Creando base de datos y usuario para DVWA ==="
sudo mysql -e "DROP DATABASE IF EXISTS dvwa;"
sudo mysql -e "CREATE DATABASE dvwa;"
sudo mysql -e "DROP USER IF EXISTS 'dvwa'@'localhost';"
sudo mysql -e "CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';"
sudo mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

echo "=== Ajustando credenciales en DVWA ==="
sudo sed -i "s/\$_DVWA\[ 'db_server' \].*/\$_DVWA[ 'db_server' ]   = '127.0.0.1';/" /var/www/html/dvwa/config/config.inc.php
sudo sed -i "s/\$_DVWA\[ 'db_database' \].*/\$_DVWA[ 'db_database' ] = 'dvwa';/" /var/www/html/dvwa/config/config.inc.php
sudo sed -i "s/\$_DVWA\[ 'db_user' \].*/\$_DVWA[ 'db_user' ]     = 'dvwa';/" /var/www/html/dvwa/config/config.inc.php
sudo sed -i "s/\$_DVWA\[ 'db_password' \].*/\$_DVWA[ 'db_password' ] = 'p@ssw0rd';/" /var/www/html/dvwa/config/config.inc.php
sudo sed -i "s/\$_DVWA\[ 'db_port' \].*/\$_DVWA[ 'db_port' ]     = '3306';/" /var/www/html/dvwa/config/config.inc.php

echo "=== Detectando versión de PHP ==="
PHPVER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
echo "PHP detectado: $PHPVER"

echo "=== Configurando PHP para Apache ==="
PHP_APACHE_INI="/etc/php/$PHPVER/apache2/php.ini"

if [ -f "$PHP_APACHE_INI" ]; then
    sudo sed -i 's/^allow_url_include = Off/allow_url_include = On/g' "$PHP_APACHE_INI"
    sudo sed -i 's/^allow_url_fopen = Off/allow_url_fopen = On/g' "$PHP_APACHE_INI"
    sudo sed -i 's/^display_errors = Off/display_errors = On/g' "$PHP_APACHE_INI"
else
    echo "Advertencia: no se encontró $PHP_APACHE_INI"
fi

echo "=== Configurando Apache ==="
sudo a2enmod rewrite
sudo systemctl restart apache2
sudo systemctl restart mariadb

echo "=== Abriendo firewall si UFW está activo ==="
sudo ufw allow 80/tcp || true
sudo ufw allow 443/tcp || true

IP=$(hostname -I | awk '{print $1}')

echo ""
echo "=========================================="
echo " DVWA instalado correctamente"
echo "=========================================="
echo ""
echo "Abre desde Ubuntu:"
echo "http://localhost/dvwa/setup.php"
echo ""
echo "Abre desde Kali:"
echo "http://$IP/dvwa/setup.php"
echo ""
echo "Usuario por defecto:"
echo "admin"
echo ""
echo "Contraseña por defecto:"
echo "password"
echo ""
echo "En setup.php presiona:"
echo "Create / Reset Database"
echo ""
echo "Después entra a DVWA Security y cambia el nivel a Low"
echo "=========================================="
