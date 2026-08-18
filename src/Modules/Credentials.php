<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;
use WP_Application_Passwords;
use WP_Session_Tokens;
use WP_User;

/**
 * Make a password reset actually revoke access.
 *
 * Core does not. wp_set_password() (wp-includes/pluggable.php:3099) writes the
 * hash, clears the activation key, cleans the user cache and fires an action —
 * that is all. There are no callers of wp_destroy_all_sessions() anywhere in
 * core, and delete_all_application_passwords() is called from exactly one place,
 * the REST controller's manual DELETE.
 *
 * So the single action a site owner takes on suspicion of compromise leaves the
 * attacker's session cookie live and their application password live. The
 * application password survives two-factor as well, because it is not a session.
 *
 * Bound to after_password_reset only, never to wp_set_password. A reset is the
 * moment someone is trying to lock an intruder out, so revoking everything is
 * what they meant. A routine profile save is not, and revoking an integration's
 * credential there would be a surprise outage.
 *
 * Two things about WooCommerce, which reimplements the reset flow rather than
 * calling core's reset_password():
 *
 * - It fires after_password_reset *before* wc_set_customer_auth_cookie(), so the
 *   customer's new session is created after this destroys the old ones and they
 *   stay logged in. That ordering is what makes this safe there; being logged out
 *   after a reset would be acceptable but is not what happens.
 * - It only started firing after_password_reset in 10.9.0. On an older
 *   WooCommerce the my-account reset path fires nothing, so this control does not
 *   run and the reset revokes nothing — the very gap it exists to close. That is
 *   a reason to keep WooCommerce current, not something this package can work
 *   around: hooking wp_set_password instead would revoke on every routine
 *   profile save.
 */
class Credentials implements Module
{
    public function register(): void
    {
        add_action('after_password_reset', [$this, 'revoke']);
    }

    public function revoke(mixed $user): void
    {
        if (! $user instanceof WP_User) {
            return;
        }

        if (class_exists(WP_Application_Passwords::class)) {
            WP_Application_Passwords::delete_all_application_passwords($user->ID);
        }

        WP_Session_Tokens::get_instance($user->ID)->destroy_all();

        /**
         * Fires when a password reset revoked a user's other credentials.
         *
         * The package does not decide where this goes — a site wires it to
         * whatever it logs to. It matters because the revocation is otherwise
         * invisible: an integration authenticating with that user's application
         * password starts returning 401 with nothing to explain it.
         *
         * @param  int  $user_id
         */
        do_action('gds_security_hardening_credentials_revoked', $user->ID);
    }
}
