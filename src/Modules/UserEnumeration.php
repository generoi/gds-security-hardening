<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;
use WP_Error;

class UserEnumeration implements Module
{
    public function register(): void
    {
        add_action('init', [$this, 'maybeDropAuthorQueryVars']);
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
     * Do not reveal whether a username exists when a login fails.
     *
     * @param  string  $message
     */
    public function genericLoginError($message): string
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

        return (string) $message;
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
