<?php

/**
 * The suite is integration-shaped on purpose.
 *
 * Every defect this package was written to avoid was invisible to a unit test:
 * the application-password recursion needed real user_has_cap callbacks, the
 * rest_pre_dispatch rejection being discarded needed another plugin registered on
 * the same filter, and the upload gate breaking public form uploads needed a form
 * plugin's own validation path. A suite that mocks WordPress would be green and
 * worthless.
 */
$autoload = dirname(__DIR__).'/vendor/autoload.php';

if (! file_exists($autoload)) {
    exit("Run `composer install` first.\n");
}

require_once $autoload;

$wpPhpunit = getenv('WP_PHPUNIT__DIR') ?: dirname(__DIR__).'/vendor/wp-phpunit/wp-phpunit';

require_once $wpPhpunit.'/includes/functions.php';

tests_add_filter('muplugins_loaded', function (): void {
    require dirname(__DIR__).'/wp-security-hardening.php';
});

require $wpPhpunit.'/includes/bootstrap.php';
