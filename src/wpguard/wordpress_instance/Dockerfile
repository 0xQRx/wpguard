FROM wordpress:php8.5-apache

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

# Xdebug for deep function-level data-flow tracing (trigger-gated; idle unless
# a request carries the XDEBUG_TRACE=wpguard trigger — see wpguard-xdebug.ini).
RUN (pecl install xdebug || true) && docker-php-ext-enable xdebug
COPY wpguard-xdebug.ini /usr/local/etc/php/conf.d/98-wpguard-xdebug.ini

# Dynamic sink tracer (WordPress-hook-level data-flow oracle). Baked into the
# image; the entrypoint copies it into mu-plugins. Off unless the flag file
# exists (managed by the wpguard_sink_trace MCP tool).
COPY wpguard-sink-trace.php /usr/local/share/wpguard-sink-trace.php

# Handle alternate PHP extensions (.php5, .phtml, .pht, etc.) for upload bypass testing
COPY wpguard-php-extensions.conf /etc/apache2/conf-enabled/wpguard-php-extensions.conf

# Ensure log directories exist with correct permissions
RUN mkdir -p /var/log/apache2 /var/log/wpguard \
    && chown www-data:www-data /var/log/apache2 /var/log/wpguard

# Install progpilot for PHP taint analysis
RUN curl -sL https://github.com/designsecurity/progpilot/releases/download/v1.3.0/progpilot_v1.3.0.phar -o /usr/local/bin/progpilot \
    && chmod +x /usr/local/bin/progpilot

# Copy custom entrypoint
COPY custom-entrypoint.sh /usr/local/bin/custom-entrypoint.sh
RUN chmod +x /usr/local/bin/custom-entrypoint.sh

ENTRYPOINT ["custom-entrypoint.sh"]
