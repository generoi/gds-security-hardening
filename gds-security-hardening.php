<?php

/*
Plugin Name:  Security Hardening
Plugin URI:   https://github.com/generoi/gds-security-hardening
Description:  Security hardening that takes no per-site configuration
Version:      1.0.0
Author:       Genero
Author URI:   https://genero.fi/
License:      MIT
*/

use GeneroWP\SecurityHardening\Plugin;

if (! defined('ABSPATH')) {
    exit;
}

if (file_exists(__DIR__.'/vendor/autoload.php')) {
    require_once __DIR__.'/vendor/autoload.php';
}

/*
 * XML-RPC is refused before anything else registers, so an XML-RPC request does
 * no work at all. Everything else needs a booted install.
 */
if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
    exit;
}

if (! function_exists('is_blog_installed') || ! is_blog_installed()) {
    return;
}

/*
 * Deferred to muplugins_loaded so the modules filter is reachable.
 *
 * Booting at file scope means only an mu-plugin sorting alphabetically before
 * this one could register gds_security_hardening_modules, which is a silent trap
 * — the documented escape hatch would work or not depending on a filename.
 *
 * muplugins_loaded rather than plugins_loaded: mu-plugins are the trusted layer,
 * they cannot be deactivated from the admin, and a regular plugin should not be
 * able to switch a security control off. Everything registered here is a filter
 * or an action that fires later; the one thing that must happen immediately, the
 * XML-RPC exit, is above.
 */
add_action('muplugins_loaded', [Plugin::class, 'boot']);
