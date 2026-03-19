#!/bin/bash

# Configuration
SITE_URL="http://172.17.0.1:8000"
SITE_TITLE="WPGuard Test Site"
ADMIN_USER="admin"
ADMIN_PASSWORD="admin"
ADMIN_EMAIL="admin@localhost.local"

setup_wordpress() {
    # Wait for WordPress files to be copied by docker-entrypoint
    echo "[WP-Setup] Waiting for WordPress files..."
    while [ ! -f /var/www/html/wp-includes/version.php ]; do
        sleep 2
    done
    echo "[WP-Setup] WordPress files found!"

    cd /var/www/html

    # Wait for database connection
    echo "[WP-Setup] Waiting for database connection..."
    while ! mysqladmin ping -h"db" --skip-ssl --silent 2>/dev/null; do
        sleep 2
    done
    echo "[WP-Setup] Database is ready!"

    # Wait for wp-config.php to be created by docker-entrypoint
    echo "[WP-Setup] Waiting for wp-config.php..."
    while [ ! -f /var/www/html/wp-config.php ]; do
        sleep 2
    done
    echo "[WP-Setup] wp-config.php found!"

    # Small delay to ensure wp-config.php is fully written
    sleep 2

    # Check if WordPress is already installed
    if wp core is-installed --allow-root 2>/dev/null; then
        echo "[WP-Setup] WordPress already installed, updating configuration..."
    else
        echo "[WP-Setup] Installing WordPress..."
        wp core install \
            --url="$SITE_URL" \
            --title="$SITE_TITLE" \
            --admin_user="$ADMIN_USER" \
            --admin_password="$ADMIN_PASSWORD" \
            --admin_email="$ADMIN_EMAIL" \
            --skip-email \
            --allow-root
    fi

    # Set site URL to Docker host IP
    echo "[WP-Setup] Configuring site URLs..."
    wp option update siteurl "$SITE_URL" --allow-root
    wp option update home "$SITE_URL" --allow-root

    # Enable pretty permalinks (required for REST API)
    echo "[WP-Setup] Enabling pretty permalinks..."
    wp rewrite structure '/%postname%/' --allow-root
    wp rewrite flush --hard --allow-root

    # Create test users for each role
    echo "[WP-Setup] Creating test users..."
    wp user create subscriber subscriber@localhost.local --role=subscriber --user_pass=subscriber --allow-root 2>/dev/null || true
    wp user create contributor contributor@localhost.local --role=contributor --user_pass=contributor --allow-root 2>/dev/null || true
    wp user create author author@localhost.local --role=author --user_pass=author --allow-root 2>/dev/null || true
    wp user create editor editor@localhost.local --role=editor --user_pass=editor --allow-root 2>/dev/null || true

    # Overwrite wp-config.php with hardcoded credentials (mirrors real-world installs)
    # Done AFTER wp core install so docker-entrypoint.sh won't overwrite our version
    echo "[WP-Setup] Writing realistic wp-config.php..."
    cat > /var/www/html/wp-config.php << 'WPCONFIG'
<?php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wp_user' );
define( 'DB_PASSWORD', 'wp_pass' );
define( 'DB_HOST', 'db:3306' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

define( 'AUTH_KEY',         'wpguard-test-auth-key-not-for-production' );
define( 'SECURE_AUTH_KEY',  'wpguard-test-secure-auth-key' );
define( 'LOGGED_IN_KEY',    'wpguard-test-logged-in-key' );
define( 'NONCE_KEY',        'wpguard-test-nonce-key' );
define( 'AUTH_SALT',        'wpguard-test-auth-salt' );
define( 'SECURE_AUTH_SALT', 'wpguard-test-secure-auth-salt' );
define( 'LOGGED_IN_SALT',   'wpguard-test-logged-in-salt' );
define( 'NONCE_SALT',       'wpguard-test-nonce-salt' );

$table_prefix = 'wp_';

define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );

if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
WPCONFIG
    chown www-data:www-data /var/www/html/wp-config.php

    echo "[WP-Setup] =========================================="
    echo "[WP-Setup] WordPress setup complete!"
    echo "[WP-Setup] Site URL: $SITE_URL"
    echo "[WP-Setup] Admin login: $ADMIN_USER / $ADMIN_PASSWORD"
    echo "[WP-Setup] Test users: subscriber, contributor, author, editor (password = username)"
    echo "[WP-Setup] REST API: $SITE_URL/wp-json/"
    echo "[WP-Setup] =========================================="
}

# Replace Apache log symlinks with real files, tail to stdout/stderr
for logfile in access.log error.log other_vhosts_access.log; do
    rm -f /var/log/apache2/$logfile
    touch /var/log/apache2/$logfile
    chown www-data:www-data /var/log/apache2/$logfile
done
tail -f /var/log/apache2/access.log /var/log/apache2/other_vhosts_access.log >/dev/stdout 2>/dev/null &
tail -f /var/log/apache2/error.log >/dev/stderr 2>/dev/null &

# Run setup in background so it doesn't block Apache startup
setup_wordpress &

# Call the original WordPress entrypoint with apache
exec docker-entrypoint.sh apache2-foreground
