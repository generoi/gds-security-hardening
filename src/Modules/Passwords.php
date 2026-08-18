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
                __('<strong>Error</strong>: Password must be at least %d characters long.', 'gds-security-hardening'),
                self::MINIMUM_LENGTH,
            ));
        }

        return null;
    }

    public function validateReset(mixed $errors, mixed $user = null): mixed
    {
        $this->addErrors($errors);

        return $errors;
    }

    public function validateProfileUpdate(mixed $errors, mixed $update = null, mixed $user = null): void
    {
        $this->addErrors($errors);
    }

    public function validateRegistration(mixed $errors, mixed $login = null, mixed $email = null): mixed
    {
        $this->addErrors($errors);

        return $errors;
    }

    protected function addErrors(mixed $errors): void
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
     * strict Content-Security-Policy.
     */
    public function enqueueHideWeakOptIn(string $hook): void
    {
        if (! in_array($hook, ['user-edit.php', 'user-new.php', 'profile.php'], true)) {
            return;
        }

        wp_enqueue_script(
            'gds-security-hardening-password',
            plugins_url('assets/hide-weak-password.js', dirname(__DIR__).'/gds-security-hardening.php'),
            [],
            null,
            true,
        );
    }
}
