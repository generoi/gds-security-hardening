<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\UserEnumeration;
use WP_Application_Passwords;
use WP_Session_Tokens;
use WP_UnitTestCase;

class CredentialsTest extends WP_UnitTestCase
{
    /**
     * Core does neither of these itself: wp_set_password() only writes the hash,
     * there are no callers of wp_destroy_all_sessions() anywhere in core, and
     * delete_all_application_passwords() is called only from the REST controller.
     * So without this, resetting a password locks nobody out.
     */
    public function test_a_password_reset_revokes_application_passwords_and_sessions(): void
    {
        $user = self::factory()->user->create_and_get(['role' => 'administrator']);

        WP_Application_Passwords::create_new_application_password($user->ID, ['name' => 'integration']);
        WP_Session_Tokens::get_instance($user->ID)->create(time() + 3600);

        $this->assertNotEmpty(WP_Application_Passwords::get_user_application_passwords($user->ID));

        do_action('after_password_reset', $user, 'a-new-password-here');

        $this->assertSame([], WP_Application_Passwords::get_user_application_passwords($user->ID));
        $this->assertEmpty(get_user_meta($user->ID, 'session_tokens', true));
    }

    public function test_it_fires_an_action_so_the_revocation_is_not_invisible(): void
    {
        $user = self::factory()->user->create_and_get(['role' => 'administrator']);
        $fired = [];
        $callback = function ($id) use (&$fired) {
            $fired[] = $id;
        };
        add_action('gds_security_hardening_credentials_revoked', $callback);

        do_action('after_password_reset', $user, 'a-new-password-here');

        remove_action('gds_security_hardening_credentials_revoked', $callback);

        $this->assertSame([$user->ID], $fired);
    }

    /**
     * A routine profile save is not someone locking an intruder out, so an
     * integration's credential must survive it.
     */
    public function test_a_plain_password_change_does_not_revoke_anything(): void
    {
        $user = self::factory()->user->create_and_get(['role' => 'administrator']);
        WP_Application_Passwords::create_new_application_password($user->ID, ['name' => 'integration']);

        wp_set_password('another-password-here', $user->ID);

        $this->assertNotEmpty(WP_Application_Passwords::get_user_application_passwords($user->ID));
    }

    /**
     * The login_errors filter only runs on wp-login.php, so anything calling
     * wp_signon() — WooCommerce's my-account form throws the message verbatim —
     * renders core's own text, which names the account.
     */
    public function test_wp_signon_does_not_reveal_whether_an_account_exists(): void
    {
        self::factory()->user->create(['user_login' => 'realuser', 'user_pass' => 'correct-horse-battery']);

        $unknown = wp_signon(['user_login' => 'nosuchuser', 'user_password' => 'whatever']);
        $wrongPassword = wp_signon(['user_login' => 'realuser', 'user_password' => 'wrong']);

        $this->assertWPError($unknown);
        $this->assertWPError($wrongPassword);
        $this->assertStringNotContainsString('nosuchuser', $unknown->get_error_message());
        $this->assertStringNotContainsString('is not registered', $unknown->get_error_message());
        $this->assertSame($unknown->get_error_message(), $wrongPassword->get_error_message());
    }

    /**
     * The code is left alone on purpose — plugins branch on it, and a limiter
     * counting incorrect_password separately is reasonable.
     */
    public function test_it_preserves_the_error_code(): void
    {
        self::factory()->user->create(['user_login' => 'realuser2', 'user_pass' => 'correct-horse-battery']);

        $this->assertContains(
            'incorrect_password',
            wp_signon(['user_login' => 'realuser2', 'user_password' => 'wrong'])->get_error_codes(),
        );
    }

    /**
     * WooCommerce reimplements the reset flow rather than calling core's
     * reset_password(), and only started firing after_password_reset in 10.9.0.
     * This runs its real method, so if that parity is ever dropped the coverage
     * gap shows up here rather than in production.
     */
    public function test_the_woocommerce_reset_flow_revokes_application_passwords(): void
    {
        if (! class_exists(\WC_Shortcode_My_Account::class)) {
            $this->markTestSkipped('WooCommerce is not loaded.');
        }

        $user = self::factory()->user->create_and_get(['role' => 'administrator']);
        WP_Application_Passwords::create_new_application_password($user->ID, ['name' => 'integration']);

        try {
            \WC_Shortcode_My_Account::reset_password($user, 'a-new-password-entirely');
        } catch (\Throwable $e) {
            // wc_setcookie() runs after the revocation and cannot send headers
            // under CLI. The part being tested has already happened.
            $this->assertStringContainsString('headers already sent', $e->getMessage());
        }

        $this->assertSame([], WP_Application_Passwords::get_user_application_passwords($user->ID));
    }

    public function test_it_leaves_other_authentication_errors_untouched(): void
    {
        $error = new \WP_Error('too_many_retries', 'Blocked by the login limiter.');

        $this->assertSame(
            'Blocked by the login limiter.',
            (new UserEnumeration)->genericAuthenticationError($error)->get_error_message(),
        );
    }
}
