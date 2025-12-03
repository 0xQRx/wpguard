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

    echo "[WP-Setup] =========================================="
    echo "[WP-Setup] WordPress setup complete!"
    echo "[WP-Setup] Site URL: $SITE_URL"
    echo "[WP-Setup] Admin login: $ADMIN_USER / $ADMIN_PASSWORD"
    echo "[WP-Setup] Test users: subscriber, contributor, author, editor (password = username)"
    echo "[WP-Setup] REST API: $SITE_URL/wp-json/"
    echo "[WP-Setup] =========================================="
}

# Run setup in background so it doesn't block Apache startup
setup_wordpress &

# Call the original WordPress entrypoint with apache
exec docker-entrypoint.sh apache2-foreground
