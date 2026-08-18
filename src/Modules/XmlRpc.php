<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;

/**
 * Disable XML-RPC, and stop advertising it.
 *
 * The entry file exits on XMLRPC_REQUEST before this loads, which covers
 * xmlrpc.php itself, and the filter covers everything that asks whether XML-RPC
 * is available.
 *
 * Neither stops core telling the world the endpoint is there. rsd_link is still
 * hooked to wp_head in default-filters.php and prints
 * <link rel="EditURI" href=".../xmlrpc.php?rsd">, and WP::send_headers() sets
 * X-Pingback on every singular view — its condition is pings_open(), not whether
 * XML-RPC is enabled (class-wp.php). Both are removed here.
 */
class XmlRpc implements Module
{
    public function register(): void
    {
        add_filter('xmlrpc_enabled', '__return_false');

        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wlwmanifest_link');

        add_filter('wp_headers', [$this, 'removePingbackHeader']);
    }

    /**
     * @param  array<string, string>  $headers
     * @return array<string, string>
     */
    public function removePingbackHeader(array $headers): array
    {
        unset($headers['X-Pingback']);

        return $headers;
    }
}
