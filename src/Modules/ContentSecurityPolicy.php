<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;

/**
 * A Content-Security-Policy for wp-admin and wp-login.php.
 *
 * Both screens are handled by one module on purpose: they send the same header,
 * so two modules racing to set it would silently replace each other.
 *
 * The frontend is out of scope — its policy depends entirely on which analytics,
 * embeds and tag managers a site runs, which is exactly the per-site judgement
 * this package avoids.
 */
class ContentSecurityPolicy implements Module
{
    /**
     * Directives that need no per-site verification.
     *
     * `frame-ancestors 'self'` only restates the header core already sends from
     * send_frame_options_header(). It stays 'self' rather than 'none' because
     * core frames this page itself: wp_auth_check_html() embeds
     * wp-login.php?interim-login=1 on every admin screen so the session-expired
     * modal can re-authenticate in place.
     *
     * @var string[]
     */
    public const DIRECTIVES = [
        "base-uri 'self'",
        "frame-ancestors 'self'",
    ];

    /**
     * Additional directives for wp-admin only.
     *
     * object-src governs <object>, <embed> and <applet>, and 'none' is wrong here:
     * core's own core/file block renders a PDF preview as
     * <object type="application/pdf"> (wp-includes/blocks/file.php reaches for the
     * OBJECT element by name), both in the editor canvas and on the frontend. Under
     * 'none' the editor shows a silent gap the height of the block where the
     * document used to be, and an author replacing the file gets no confirmation
     * that anything happened. That is not a plugin screen anyone could sweep for —
     * it is core, on the post editor, on any site that attaches documents to posts.
     *
     * 'self' keeps what the directive is worth having for: an injected <object>
     * pointing at an attacker's host is still refused, and so is the Flash and Java
     * era markup the element mostly exists for. What it permits is a same-origin
     * document, which is what core embeds. Reaching it means already being able to
     * put a file in the media library.
     *
     * @var string[]
     */
    public const ADMIN_DIRECTIVES = [
        "object-src 'self'",
    ];

    /**
     * Additional directives for wp-login.php only.
     *
     * form-action can be locked here, unlike in the admin: every form on the
     * login screen posts back to wp-login.php, with no plugin onboarding flows to
     * guess about.
     *
     * object-src can stay at 'none' here for the same reason: nothing on the login
     * screen embeds a document, so there is no core behaviour to leave room for.
     *
     * @var string[]
     */
    public const LOGIN_DIRECTIVES = [
        "form-action 'self'",
        "object-src 'none'",
    ];

    protected ?string $nonce = null;

    public function register(): void
    {
        // Priority 11, after core's send_frame_options_header() at 10, which
        // sends a Content-Security-Policy of its own and would replace ours.
        add_action('admin_init', [$this, 'sendAdminPolicy'], 11);
        add_action('login_init', [$this, 'sendLoginPolicy'], 11);
    }

    /**
     * One value per request, so every script tag carries the same nonce as the
     * header.
     */
    public function nonce(): string
    {
        return $this->nonce ??= bin2hex(random_bytes(16));
    }

    /**
     * wp-admin gets no script policy.
     *
     * It cannot take a nonce: core alone prints around a dozen un-nonced inline
     * scripts per screen (core #59446) and the media library needs eval (core
     * #62894). The nonce-free alternative, `script-src-elem 'self'
     * 'unsafe-inline'`, blocks external `<script src>`, which plugins
     * legitimately use on their own admin screens — enforcing it safely needs a
     * per-site plugin sweep, which is what this package does not do.
     */
    public function sendAdminPolicy(): void
    {
        $this->send([
            ...self::DIRECTIVES,
            ...self::ADMIN_DIRECTIVES,
        ]);
    }

    /**
     * wp-login.php gets a full Strict CSP: nonce plus strict-dynamic, no
     * unsafe-inline.
     *
     * Nothing without this request's nonce executes — injected script tags,
     * inline handlers, javascript: URIs and eval all fail — which is what stops
     * an injected script reading the password field on submit. The credential
     * entry page is worth the stricter policy, and core has supported one here
     * since 6.4.
     *
     * strict-dynamic lets the nonced bootstrap scripts load their own
     * dependencies, which is how the wp-includes/js/dist chain loads.
     *
     * Known cost: a plugin that prints a raw <script> on this screen breaks.
     * limit-login-attempts-reloaded does exactly that when credentials are
     * submitted, so its login screen needs a patch, or its markup needs to go
     * through wp_print_inline_script_tag().
     */
    public function sendLoginPolicy(): void
    {
        add_filter('wp_script_attributes', [$this, 'addNonce']);
        add_filter('wp_inline_script_attributes', [$this, 'addNonce']);

        $this->send([
            ...self::DIRECTIVES,
            ...self::LOGIN_DIRECTIVES,
            sprintf("script-src 'nonce-%s' 'strict-dynamic'", $this->nonce()),
        ]);
    }

    /**
     * Core keys these by attribute name, and a value may be a bool for the
     * valueless ones such as `async`.
     *
     * @param  array<string, mixed>  $attributes
     * @return array<string, mixed>
     */
    public function addNonce(array $attributes): array
    {
        $attributes['nonce'] = $this->nonce();

        return $attributes;
    }

    /**
     * @param  string[]  $directives
     */
    protected function send(array $directives): void
    {
        if (headers_sent() || wp_doing_ajax() || wp_is_rest_endpoint()) {
            return;
        }

        // Would break a plain-http local environment.
        if (is_ssl()) {
            $directives[] = 'upgrade-insecure-requests';
        }

        $policy = implode('; ', apply_filters('gds_security_hardening_csp_directives', $directives));

        header("Content-Security-Policy: {$policy}");
    }
}
