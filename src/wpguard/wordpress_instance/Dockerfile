FROM wordpress:latest

# Install utilities and WP-CLI
RUN apt-get update && apt-get install -y less vim default-mysql-client && rm -rf /var/lib/apt/lists/*
RUN curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
 && chmod +x wp-cli.phar \
 && mv wp-cli.phar /usr/local/bin/wp

# PHP extensions commonly needed by WordPress plugins
RUN apt-get update && apt-get install -y \
    libmagickwand-dev libxml2-dev libzip-dev libpng-dev libjpeg-dev libfreetype6-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install soap zip exif gd \
    && (pecl install imagick || true) && docker-php-ext-enable imagick \
    && rm -rf /var/lib/apt/lists/*

# Permissive PHP config for PoC testing (NOT standard WordPress)
COPY php-custom.ini /usr/local/etc/php/conf.d/99-wpguard.ini

# Handle alternate PHP extensions (.php5, .phtml, .pht, etc.) for upload bypass testing
COPY wpguard-php-extensions.conf /etc/apache2/conf-enabled/wpguard-php-extensions.conf

# Ensure log directories exist with correct permissions
RUN mkdir -p /var/log/apache2 /var/log/wpguard \
    && chown www-data:www-data /var/log/apache2 /var/log/wpguard

# Copy custom entrypoint
COPY custom-entrypoint.sh /usr/local/bin/custom-entrypoint.sh
RUN chmod +x /usr/local/bin/custom-entrypoint.sh

ENTRYPOINT ["custom-entrypoint.sh"]
