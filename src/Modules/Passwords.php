<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;
use WP_Error;
use WP_REST_Request;
use WP_REST_Users_Controller;

/**
 * Enforce a minimum password length, server side.
 *
 * Removing the "Confirm use of weak password" checkbox is UX, not enforcement —
 * it changes nothing about what the server accepts. The filters below are where
 * enforcement happens; the checkbox is hidden as well so nobody is offered an
 * option that will be rejected.
 *
 * Covering the flows rather than one field name is the point. Core's three hooks
 * only fire from wp-login.php, edit_user() and register_new_user(); WooCommerce
 * posts `password_1` through its own reset and account-details handlers, and the
 * REST user routes go through wp_insert_user(), which fires none of them.
 */
class Passwords implements Module
{
    public const MINIMUM_LENGTH = 12;

    /**
     * Field names the password arrives under, across core and WooCommerce.
     *
     * @var string[]
     */
    public const FIELDS = ['pass1', 'password_1'];

    public function register(): void
    {
        add_filter('validate_password_reset', [$this, 'validateReset'], 10, 2);
        add_action('user_profile_update_errors', [$this, 'validateProfileUpdate'], 10, 3);
        add_filter('registration_errors', [$this, 'validateRegistration'], 10, 3);

        // WooCommerce's account-details save fires none of core's three.
        add_action('woocommerce_save_account_details_errors', [$this, 'validateProfileUpdate'], 10, 2);

        // rest_pre_insert_user only transforms data; its caller does not check
        // for WP_Error. Reject before the controller can write anything.
        add_filter('rest_request_before_callbacks', [$this, 'validateRestUser'], 10, 3);

        add_action('admin_enqueue_scripts', [$this, 'enqueueHideWeakOptIn']);
    }

    /**
     * Null when the password is acceptable.
     */
    public function validate(string $password): ?WP_Error
    {
        // mb_strlen, not strlen: the latter counts bytes, so four emoji would
        // pass a twelve-character minimum.
        if (mb_strlen($password) < self::MINIMUM_LENGTH) {
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

    /**
     * @param  array<string, mixed>  $handler
     * @return mixed WP_Error to refuse the write, the previous response otherwise
     */
    public function validateRestUser(mixed $response, array $handler, WP_REST_Request $request): mixed
    {
        $callback = $handler['callback'] ?? null;
        $controller = is_array($callback) ? ($callback[0] ?? null) : null;

        if ($response instanceof WP_Error || ! $controller instanceof WP_REST_Users_Controller
            || ! in_array($request->get_method(), ['POST', 'PUT', 'PATCH'], true)) {
            return $response;
        }

        $password = $request['password'];

        if (! is_string($password) || $password === '') {
            return $response;
        }

        $error = $this->validate($password);

        if ($error) {
            $error->add_data(['status' => 400]);
        }

        return $error ?? $response;
    }

    /**
     * The submitted password, exactly as typed.
     *
     * Deliberately not sanitised. sanitize_text_field() strips tags and collapses
     * whitespace, so it measures a mangled copy — "<script>abcd1234" is sixteen
     * characters and would be rejected as eight — while the password that
     * actually gets stored is never sanitised.
     */
    protected function submittedPassword(): ?string
    {
        foreach (self::FIELDS as $field) {
            if (! empty($_POST[$field]) && is_string($_POST[$field])) {
                return wp_unslash($_POST[$field]);
            }
        }

        return null;
    }

    protected function addErrors(mixed $errors): void
    {
        $password = $this->submittedPassword();

        if (! $errors instanceof WP_Error || $password === null) {
            return;
        }

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
            plugins_url('assets/hide-weak-password.js', dirname(__DIR__, 2).'/gds-security-hardening.php'),
            [],
            null,
            true,
        );
    }
}
