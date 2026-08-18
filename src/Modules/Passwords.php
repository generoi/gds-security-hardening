<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;
use WP_Error;

/**
 * Enforce a minimum password length, server side.
 *
 * Removing the "Confirm use of weak password" checkbox is UX, not enforcement —
 * it changes nothing about what the server accepts. The three filters below are
 * where enforcement happens; the checkbox is hidden as well so nobody is offered
 * an option that will be rejected.
 */
class Passwords implements Module
{
    public const MINIMUM_LENGTH = 12;

    public function register(): void
    {
        add_filter('validate_password_reset', [$this, 'validateReset'], 10, 2);
        add_action('user_profile_update_errors', [$this, 'validateProfileUpdate'], 10, 3);
        add_filter('registration_errors', [$this, 'validateRegistration'], 10, 3);
        add_action('admin_enqueue_scripts', [$this, 'enqueueHideWeakOptIn']);
    }

    /**
     * Null when the password is acceptable.
     */
    public function validate(string $password): ?WP_Error
    {
        if (strlen($password) < self::MINIMUM_LENGTH) {
            return new WP_Error('password_too_short', sprintf(
                /* translators: %d: minimum number of characters */
                __('<strong>Error</strong>: Password must be at least %d characters long.', 'wp-security-hardening'),
                self::MINIMUM_LENGTH,
            ));
        }

        return null;
    }

    /**
     * @param  mixed  $errors
     * @param  mixed  $user
     * @return mixed
     */
    public function validateReset($errors, $user = null)
    {
        $this->addErrors($errors);

        return $errors;
    }

    /**
     * @param  mixed  $errors
     * @param  mixed  $update
     * @param  mixed  $user
     */
    public function validateProfileUpdate($errors, $update = null, $user = null): void
    {
        $this->addErrors($errors);
    }

    /**
     * @param  mixed  $errors
     * @param  mixed  $login
     * @param  mixed  $email
     * @return mixed
     */
    public function validateRegistration($errors, $login = null, $email = null)
    {
        $this->addErrors($errors);

        return $errors;
    }

    /**
     * @param  mixed  $errors
     */
    protected function addErrors($errors): void
    {
        if (! $errors instanceof WP_Error || empty($_POST['pass1'])) {
            return;
        }

        $password = sanitize_text_field(wp_unslash($_POST['pass1']));
        $result = $this->validate($password);

        if (! $result instanceof WP_Error) {
            return;
        }

        foreach ($result->get_error_codes() as $code) {
            $errors->add($code, $result->get_error_message($code));
        }
    }

    /**
     * Hide the "Confirm use of weak password" opt-in.
     *
     * A real file rather than an echoed <script>, so it can carry a nonce under a
     * strict Content-Security-Policy. The previous inline version could not.
     *
     * @param  string  $hook
     */
    public function enqueueHideWeakOptIn($hook): void
    {
        if (! in_array($hook, ['user-edit.php', 'user-new.php', 'profile.php'], true)) {
            return;
        }

        wp_enqueue_script(
            'wp-security-hardening-password',
            plugins_url('assets/hide-weak-password.js', dirname(__DIR__).'/wp-security-hardening.php'),
            [],
            null,
            true,
        );
    }
}
