FROM php:8.1-apache

RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
RUN sed -i 's/Listen 80/Listen 1337/g' /etc/apache2/ports.conf
RUN docker-php-ext-install mysqli

COPY src/* /var/www/html/
