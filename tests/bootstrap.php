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
    require dirname(__DIR__).'/gds-security-hardening.php';
});

require $wpPhpunit.'/includes/bootstrap.php';
