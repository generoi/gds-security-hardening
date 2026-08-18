<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;
use WP_Error;

class UserEnumeration implements Module
{
    /**
     * Error codes that answer "does this account exist?".
     *
     * @var string[]
     */
    public const REVEALING_CODES = ['invalid_username', 'invalid_email', 'incorrect_password'];

    public function register(): void
    {
        add_action('init', [$this, 'maybeDropAuthorQueryVars']);

        // Priority 100: after every core authenticator (20 and 30) and after
        // wp_authenticate_spam_check (99).
        add_filter('authenticate', [$this, 'genericAuthenticationError'], 100, 2);
        add_filter('login_errors', [$this, 'genericLoginError']);
        add_action('lost_password', [$this, 'alwaysRedirectLostPassword']);
    }

    /**
     * Stop ?author=<id> resolving to an author archive.
     *
     * The narrow arming condition is deliberate — do not widen it to catch
     * `author_name=` on its own. WP::parse_request() copies rewrite matches into
     * query_vars from inside its `foreach ($this->public_query_vars ...)` loop,
     * which runs *after* the query_vars filter. Dropping author_name
     * unconditionally would therefore break the /author/nicename/ archive route as
     * well, not just the query-string form.
     *
     * Arming only when `author=<id>` is present kills the vector that actually
     * enumerates — the numeric id core 301-redirects to a URL containing the
     * username — and leaves author archives working.
     */
    public function maybeDropAuthorQueryVars(): void
    {
        if (is_admin()) {
            return;
        }

        $queryString = isset($_SERVER['QUERY_STRING'])
            ? sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING']))
            : '';

        if (! preg_match('/author=([0-9]*)/i', $queryString)) {
            return;
        }

        add_filter('query_vars', function (array $queryVars): array {
            return array_values(array_diff($queryVars, ['author', 'author_name']));
        });
    }

    /**
     * Do not reveal whether an account exists to anything that calls wp_signon().
     *
     * The login_errors filter below is not enough on its own: core applies it in
     * exactly one place, wp-login.php, so every other login form in WordPress
     * renders core's own message. And core's message names the account —
     * "The username <strong>bob</strong> is not registered on this site"
     * (wp-includes/user.php:185-188).
     *
     * WooCommerce is the case that matters here. Its my-account form calls
     * wp_signon() and throws $user->get_error_message() verbatim, with no branch
     * on the code (includes/class-wc-form-handler.php:1076-1079), so every
     * WooCommerce login form answers "does this account exist?" for anyone who
     * asks. Gravity Forms' user-registration login and any theme login form do
     * the same.
     *
     * The message is replaced and the code is left alone, deliberately. The code
     * is not rendered anywhere, while plugins do branch on it — a brute-force
     * limiter counting incorrect_password separately from invalid_username is a
     * reasonable thing to do, and rewriting the code would break it silently.
     *
     * A timing oracle survives this: core returns before wp_check_password() when
     * the account does not exist, so an unknown username answers faster. Closing
     * that means burning a hash round on every invalid-username attempt, which is
     * self-inflicted CPU amplification for an attacker to trigger. Not worth it.
     *
     * @param  mixed  $user  WP_User, WP_Error or null
     */
    public function genericAuthenticationError(mixed $user, string $username = ''): mixed
    {
        if (! $user instanceof WP_Error) {
            return $user;
        }

        $revealing = array_intersect(self::REVEALING_CODES, $user->get_error_codes());

        if ($revealing === []) {
            return $user;
        }

        $message = __('<strong>Error:</strong> Invalid username, email address or password.', 'gds-security-hardening');

        foreach ($revealing as $code) {
            $data = $user->get_error_data($code);
            $user->remove($code);
            $user->add($code, $message, $data);
        }

        return $user;
    }

    /**
     * Do not reveal whether a username exists when a login fails.
     */
    public function genericLoginError(string $message): string
    {
        global $errors;

        if (isset($errors->errors['invalid_username']) || isset($errors->errors['incorrect_password'])) {
            return sprintf(
                /* translators: 1: lost password URL, 2: link title, 3: link text */
                __('<strong>ERROR</strong>: Invalid username/password combination. <a href="%1$s" title="%2$s">%3$s</a>?'),
                site_url('wp-login.php?action=lostpassword', 'login'),
                __('Password Lost and Found'),
                __('Lost Password')
            );
        }

        return $message;
    }

    /**
     * Do not reveal whether a username exists through the lost password form.
     */
    public function alwaysRedirectLostPassword(WP_Error $errors): void
    {
        if (! $errors->has_errors()) {
            return;
        }

        $redirectTo = ! empty($_REQUEST['redirect_to'])
            ? esc_url_raw(wp_unslash($_REQUEST['redirect_to']))
            : 'wp-login.php?checkemail=confirm';

        wp_safe_redirect($redirectTo);
    }
}
