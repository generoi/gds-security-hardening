<?php

/**
 * The suite is integration-shaped on purpose.
 *
 * These controls are defined by how they interact with core's hook order and with
 * other plugins on the same hooks — filter priority, whether a capability check is
 * safe to make at a given point, which callers reach a filter. None of that is
 * observable against mocks, so the suite boots WordPress.
 */
$autoload = dirname(__DIR__).'/vendor/autoload.php';

if (! file_exists($autoload)) {
    exit("Run `composer install` first.\n");
}

require_once $autoload;

$wpPhpunit = getenv('WP_PHPUNIT__DIR') ?: dirname(__DIR__).'/vendor/wp-phpunit/wp-phpunit';

require_once $wpPhpunit.'/includes/functions.php';

tests_add_filter('muplugins_loaded', function (): void {
    /*
     * Real plugins, not doubles.
     *
     * Several controls exist because of what these do — WooCommerce posts
     * password_1 through handlers that fire none of core's password hooks, and
     * two-factor is what TwoFactor gates on — so testing them against mocks would
     * assert our reading of those plugins rather than their behaviour.
     *
     * This package installs into mu-plugins, so the plugins directory is a
     * sibling of that rather than the parent. Skipped when absent so the suite
     * still runs against a bare WordPress.
     */
    $plugins = defined('WP_PLUGIN_DIR') ? WP_PLUGIN_DIR : dirname(__DIR__, 3).'/plugins';

    foreach ([
        '/woocommerce.10.9.4/woocommerce.php',
        '/woocommerce/woocommerce.php',
        '/two-factor.latest-stable/two-factor.php',
        '/two-factor/two-factor.php',
    ] as $plugin) {
        if (file_exists($plugins.$plugin)) {
            require_once $plugins.$plugin;
        }
    }

    require dirname(__DIR__).'/gds-security-hardening.php';
});

require $wpPhpunit.'/includes/bootstrap.php';
