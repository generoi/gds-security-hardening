<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;

/**
 * Static security headers, everywhere.
 *
 * Themes that send these typically bind to `send_headers`, which covers the
 * frontend and nothing else: wp-admin and wp-login.php run their own request
 * lifecycle, and REST reaches neither because rest_api_loaded() serves and exits
 * from inside `parse_request`, before WP::send_headers() is ever called.
 *
 * nosniff matters most on REST. With JSONP disabled a REST response is
 * application/json, and nosniff is what makes `<script src="/wp-json/...">` fail
 * outright instead of being sniffed into script. The two are only worth much
 * together.
 *
 * A theme sending the same headers is not a conflict: header() replaces rather
 * than appends.
 */
class Headers implements Module
{
    /** @var array<string, string> */
    public const HEADERS = [
        // Force client-side TLS redirection.
        'Strict-Transport-Security' => 'max-age=63072000; includeSubDomains; preload',
        // Content sniffing is an attack vector.
        'X-Content-Type-Options' => 'nosniff',
        // Clickjacking. Core sends this on admin and login at priority 10 via
        // send_frame_options_header(); repeating it is harmless and covers REST,
        // which core does not.
        'X-Frame-Options' => 'SAMEORIGIN',
        // Limit referrer leakage.
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
    ];

    public function register(): void
    {
        // The frontend goes through the filter rather than header(): WP builds an
        // array in WP::send_headers() and sends it itself, so joining the array
        // leaves the headers visible and adjustable to anything else filtering
        // them, instead of being set behind their back.
        add_filter('wp_headers', [$this, 'merge']);

        // Priority 11, after core's send_frame_options_header() at 10.
        add_action('admin_init', [$this, 'send'], 11);
        add_action('login_init', [$this, 'send'], 11);

        // The last hook before a REST response is written, and it runs for every
        // route including the ones a site keeps public.
        add_filter('rest_pre_serve_request', [$this, 'sendForRest']);
    }

    /**
     * @param  array<string, string>  $headers
     * @return array<string, string>
     */
    public function merge(array $headers): array
    {
        return array_merge($headers, self::HEADERS);
    }

    public function send(): void
    {
        if (headers_sent()) {
            return;
        }

        foreach (self::HEADERS as $header => $value) {
            header("{$header}: {$value}");
        }
    }

    public function sendForRest(mixed $served): mixed
    {
        $this->send();

        return $served;
    }
}
