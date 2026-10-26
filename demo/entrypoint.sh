#!/bin/sh
set -e
mkdir -p /var/www/app/data /etc/nginx/ssl
chown -R nginx:nginx /var/www/app/data
if [ ! -f /etc/nginx/ssl/kanboard.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout /etc/nginx/ssl/kanboard.key \
    -out /etc/nginx/ssl/kanboard.crt \
    -subj "/CN=localhost" >/dev/null 2>&1
fi
php-fpm -D
exec nginx -g 'daemon off;'
