<?php

/*
Plugin Name:  Security Hardening
Plugin URI:   https://github.com/generoi/wp-security-hardening
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

Plugin::boot();
