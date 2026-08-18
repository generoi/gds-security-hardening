<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;

/**
 * A Content-Security-Policy for wp-admin and wp-login.php.
 *
 * Only the directives that need no per-site verification. Every one here is
 * something no plugin update can plausibly trip, and `frame-ancestors 'self'`
 * only restates the header core already sends from send_frame_options_header().
 *
 * It deliberately says nothing about scripts. wp-admin cannot take a nonce
 * policy — core alone prints around a dozen un-nonced inline scripts per screen
 * (core #59446) and the media library needs eval (core #62894) — and the
 * nonce-free alternative, `script-src-elem 'self' 'unsafe-inline'`, blocks
 * external `<script src>`, which plugins legitimately use on their own admin
 * screens. Enforcing that safely needs a per-site plugin sweep, which is exactly
 * what this package does not do.
 *
 * A strict script policy on wp-login.php is worth that cost, but it is a
 * different trade and lives in StrictLoginScripts, which is opt-in.
 *
 * The frontend is out of scope: its policy depends entirely on which analytics,
 * embeds and tag managers a site runs.
 */
class ContentSecurityPolicy implements Module
{
    /** @var string[] */
    public const DIRECTIVES = [
        "base-uri 'self'",
        "frame-ancestors 'self'",
        "object-src 'none'",
    ];

    public function register(): void
    {
        // Priority 11, after core's send_frame_options_header() at 10, which
        // sends a Content-Security-Policy of its own and replaces ours if it
        // runs second.
        add_action('admin_init', [$this, 'send'], 11);
        add_action('login_init', [$this, 'send'], 11);
    }

    public function send(): void
    {
        if (headers_sent() || wp_doing_ajax() || wp_is_rest_endpoint()) {
            return;
        }

        $directives = self::DIRECTIVES;

        // Would break a plain-http local environment.
        if (is_ssl()) {
            $directives[] = 'upgrade-insecure-requests';
        }

        $policy = implode('; ', apply_filters('wp_security_hardening_csp_directives', $directives));

        header("Content-Security-Policy: {$policy}");
    }
}
