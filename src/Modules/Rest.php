<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;
use WP_Error;

class Rest implements Module
{
    public function register(): void
    {
        add_filter('rest_jsonp_enabled', '__return_false');

        // PHP_INT_MAX: rest_pre_dispatch is a filter, and a later callback that
        // ignores the value handed to it silently discards ours. Polylang
        // registers four callbacks on this hook and Gravity Forms one at 99; at
        // the default priority the rejection below was measurably dropped.
        add_filter('rest_pre_dispatch', [$this, 'rejectMethodOverride'], PHP_INT_MAX);

        remove_action('template_redirect', 'rest_output_link_header', 11);
        remove_action('wp_head', 'rest_output_link_wp_head', 10);
        remove_action('xmlrpc_rsd_apis', 'rest_output_rsd');
    }

    /**
     * Refuse a read that has been overridden into a write.
     *
     * Core rewrites a REST request's verb from `?_method=` or
     * `X-HTTP-Method-Override` before dispatch, with no validation and no
     * restriction on which transitions are allowed. A plain GET therefore
     * dispatches as a write while the edge cache, CDN rules, WAF signatures and
     * the access log all see a read.
     *
     * Only that direction is refused. @wordpress/api-fetch ships httpV1Middleware
     * in its default middleware chain, rewriting every PATCH, PUT and DELETE into
     * a POST carrying the override header, and @wordpress/core-data saves an
     * existing record with PUT and deletes with DELETE. Refusing overrides
     * outright breaks every save of an existing post, page or template. A POST
     * tunnelling a PUT is also not the bug: the edge already sees a write.
     */
    public function rejectMethodOverride(mixed $result): mixed
    {
        $overridden = isset($_GET['_method']) || isset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']);
        $actual = strtoupper($_SERVER['REQUEST_METHOD'] ?? '');

        if ($overridden && in_array($actual, ['GET', 'HEAD'], true)) {
            return new WP_Error(
                'rest_method_override_disabled',
                __('A read request may not be overridden into a write.', 'wp-security-hardening'),
                ['status' => 400],
            );
        }

        return $result;
    }
}
