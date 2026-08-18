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
    /**
     * Sent everywhere.
     *
     * @var array<string, string>
     */
    public const HEADERS = [
        // Content sniffing is an attack vector.
        'X-Content-Type-Options' => 'nosniff',
        // Limit referrer leakage.
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
    ];

    /**
     * Sent on admin, login and REST only.
     *
     * Core sends X-Frame-Options on admin and login itself, from
     * send_frame_options_header(), and deliberately does not send it on the
     * frontend — a site may legitimately be embedded elsewhere. Repeating it on
     * the privileged surfaces is harmless and covers REST, which core does not;
     * asserting it on the frontend would break those embeds.
     *
     * @var array<string, string>
     */
    public const PRIVILEGED_HEADERS = [
        'X-Frame-Options' => 'SAMEORIGIN',
    ];

    /**
     * Only meaningful over TLS, and a browser ignores it on plain http anyway —
     * but sending it there would also break a local http environment.
     */
    public const STRICT_TRANSPORT_SECURITY = 'max-age=63072000; includeSubDomains; preload';

    public function register(): void
    {
        // The frontend goes through the filter rather than header(): WP builds an
        // array in WP::send_headers() and sends it itself, so joining the array
        // leaves the headers visible and adjustable to anything else filtering
        // them, instead of being set behind their back.
        add_filter('wp_headers', [$this, 'merge']);

        // Priority 11, after core's send_frame_options_header() at 10.
        add_action('admin_init', [$this, 'sendPrivileged'], 11);
        add_action('login_init', [$this, 'sendPrivileged'], 11);

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

    public function send(bool $privileged = false): void
    {
        if (headers_sent()) {
            return;
        }

        $headers = $privileged ? [...self::HEADERS, ...self::PRIVILEGED_HEADERS] : self::HEADERS;

        if (is_ssl()) {
            $headers['Strict-Transport-Security'] = self::STRICT_TRANSPORT_SECURITY;
        }

        foreach (apply_filters('gds_security_hardening_headers', $headers, $privileged) as $header => $value) {
            header("{$header}: {$value}");
        }
    }

    public function sendPrivileged(): void
    {
        $this->send(true);
    }

    public function sendForRest(mixed $served): mixed
    {
        $this->send(true);

        return $served;
    }
}
