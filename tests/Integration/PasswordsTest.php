<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\Passwords;
use WP_Error;
use WP_REST_Request;
use WP_REST_Users_Controller;
use WP_UnitTestCase;

class PasswordsTest extends WP_UnitTestCase
{
    /**
     * Long enough for this module, and strong enough for wordfence, which is
     * active in the test environment and enforces its own policy — uppercase,
     * lowercase, a symbol and a number — on the REST user routes.
     */
    public const STRONG_PASSWORD = 'Str0ng-Passw0rd!x9';

    protected Passwords $module;

    public function set_up(): void
    {
        parent::set_up();
        $this->module = new Passwords;
    }

    public function tear_down(): void
    {
        unset($_POST['pass1'], $_POST['password_1']);
        parent::tear_down();
    }

    /**
     * strlen() counts bytes, so four emoji would satisfy a twelve-character
     * minimum.
     */
    public function test_length_is_counted_in_characters_not_bytes(): void
    {
        $this->assertWPError($this->module->validate(str_repeat('🔒', 4)));
        $this->assertNull($this->module->validate(str_repeat('🔒', 12)));
    }

    /**
     * sanitize_text_field() strips tags and collapses whitespace, so validating a
     * sanitised copy measures something the user never typed and that is never
     * what gets stored.
     */
    public function test_the_password_is_measured_exactly_as_typed(): void
    {
        $_POST['pass1'] = '<script>abcd1234';
        $errors = new WP_Error;

        $this->module->validateReset($errors);

        $this->assertFalse($errors->has_errors(), 'A 16-character password was measured as its sanitised 8-character form.');
    }

    /**
     * WooCommerce posts password_1, through its own reset handler and its
     * account-details save. Core's three hooks never see pass1 there.
     */
    public function test_it_reads_the_woocommerce_field(): void
    {
        $_POST['password_1'] = 'short';
        $errors = new WP_Error;

        $this->module->validateReset($errors);

        $this->assertTrue($errors->has_errors());
        $this->assertContains('password_too_short', $errors->get_error_codes());
    }

    /**
     * POST /wp/v2/users goes through wp_insert_user(), which fires none of the
     * three hooks core applies elsewhere.
     */
    public function test_the_rest_user_route_is_covered(): void
    {
        $request = new WP_REST_Request('POST', '/wp/v2/users');
        $request->set_param('password', 'short');

        $handler = ['callback' => [new WP_REST_Users_Controller, 'create_item']];
        $error = $this->module->validateRestUser(null, $handler, $request);

        $this->assertWPError($error);
        $this->assertSame(400, $error->get_error_data()['status']);
    }

    public function test_a_long_enough_rest_password_passes_through_untouched(): void
    {
        $request = new WP_REST_Request('POST', '/wp/v2/users');
        $request->set_param('password', str_repeat('a', 12));
        $handler = ['callback' => [new WP_REST_Users_Controller, 'create_item']];

        $this->assertNull($this->module->validateRestUser(null, $handler, $request));
    }

    public function test_a_request_without_a_password_is_left_alone(): void
    {
        $errors = new WP_Error;

        $this->module->validateReset($errors);

        $this->assertFalse($errors->has_errors());
    }

    /**
     * Through the real route, not the module's method.
     */
    public function test_the_rest_users_route_refuses_a_short_password(): void
    {
        wp_set_current_user(self::factory()->user->create(['role' => 'administrator']));

        $request = new WP_REST_Request('POST', '/wp/v2/users');
        $request->set_param('username', 'restshortpw');
        $request->set_param('email', 'restshortpw@example.test');
        $request->set_param('password', 'short');

        $response = rest_do_request($request);

        $this->assertTrue($response->is_error());
        $this->assertSame(400, $response->get_status());
        $this->assertSame('password_too_short', $response->get_data()['code']);
        $this->assertFalse((bool) username_exists('restshortpw'));
    }

    public function test_the_rest_users_route_accepts_a_long_enough_password(): void
    {
        $administrator = self::factory()->user->create(['role' => 'administrator']);
        if (is_multisite()) {
            grant_super_admin($administrator);
        }
        wp_set_current_user($administrator);

        $request = new WP_REST_Request('POST', '/wp/v2/users');
        $request->set_param('username', 'restlongpw');
        $request->set_param('email', 'restlongpw@example.test');
        $request->set_param('password', self::STRONG_PASSWORD);

        $response = rest_do_request($request);

        $this->assertFalse(
            $response->is_error(),
            'A valid password was refused: '.wp_json_encode($response->get_data()),
        );
        $this->assertNotFalse(username_exists('restlongpw'));
    }

    public function test_rest_updates_reject_the_whole_write_instead_of_reporting_success(): void
    {
        $user = self::factory()->user->create_and_get(['role' => 'subscriber']);
        wp_set_current_user($user->ID);

        foreach (['/wp/v2/users/'.$user->ID, '/wp/v2/users/me'] as $route) {
            $request = new WP_REST_Request('POST', $route);
            $request->set_param('password', 'short');
            $request->set_param('name', 'Must not be saved');
            $response = rest_do_request($request);

            $this->assertSame(400, $response->get_status());
            $this->assertSame('password_too_short', $response->get_data()['code']);
            $this->assertSame($user->user_pass, get_userdata($user->ID)->user_pass);
            $this->assertSame($user->display_name, get_userdata($user->ID)->display_name);
        }
    }

    public function test_rest_updates_accept_valid_passwords_and_passwordless_profile_changes(): void
    {
        $user = self::factory()->user->create_and_get(['role' => 'subscriber']);
        wp_set_current_user($user->ID);
        $request = new WP_REST_Request('POST', '/wp/v2/users/me');
        $request->set_param('password', self::STRONG_PASSWORD);
        $response = rest_do_request($request);
        $this->assertSame(200, $response->get_status());
        $this->assertTrue(wp_check_password(self::STRONG_PASSWORD, get_userdata($user->ID)->user_pass, $user->ID));

        $request = new WP_REST_Request('POST', '/wp/v2/users/me');
        $request->set_param('name', 'Updated name');
        $this->assertSame(200, rest_do_request($request)->get_status());
        $this->assertSame('Updated name', get_userdata($user->ID)->display_name);
    }

    public function test_rest_validation_preserves_prior_results_and_ignores_other_controllers(): void
    {
        $request = new WP_REST_Request('POST', '/wp/v2/users');
        $request->set_param('password', 'short');
        $handler = ['callback' => [new WP_REST_Users_Controller, 'create_item']];
        $error = new WP_Error('other_error', 'Existing rejection', ['status' => 403]);
        $this->assertSame($error, $this->module->validateRestUser($error, $handler, $request));
        $this->assertWPError($this->module->validateRestUser(false, $handler, $request));
        $this->assertWPError($this->module->validateRestUser(true, $handler, $request));
        $this->assertNull($this->module->validateRestUser(null, ['callback' => '__return_true'], $request));
        $request->set_method('GET');
        $this->assertNull($this->module->validateRestUser(null, $handler, $request));
    }

    /**
     * WooCommerce's own hook, fired the way WooCommerce fires it
     * (class-wc-form-handler.php:334), with the field name WooCommerce posts.
     */
    public function test_woocommerce_account_details_refuse_a_short_password(): void
    {
        if (! class_exists(\WooCommerce::class)) {
            $this->markTestSkipped('WooCommerce is not loaded.');
        }

        $user = get_userdata(self::factory()->user->create(['role' => 'customer']));
        $_POST['password_1'] = 'short';
        $errors = new WP_Error;

        do_action_ref_array('woocommerce_save_account_details_errors', [&$errors, &$user]);

        $this->assertContains('password_too_short', $errors->get_error_codes());
    }

    /**
     * WooCommerce's reset handler fires core's validate_password_reset, but with
     * the password in its own field (class-wc-form-handler.php:1162).
     */
    public function test_the_woocommerce_reset_flow_refuses_a_short_password(): void
    {
        if (! class_exists(\WooCommerce::class)) {
            $this->markTestSkipped('WooCommerce is not loaded.');
        }

        $user = get_userdata(self::factory()->user->create(['role' => 'customer']));
        $_POST['password_1'] = 'short';
        $errors = new WP_Error;

        do_action('validate_password_reset', $errors, $user);

        $this->assertContains('password_too_short', $errors->get_error_codes());
    }

    public function test_the_woocommerce_reset_flow_accepts_a_long_enough_password(): void
    {
        if (! class_exists(\WooCommerce::class)) {
            $this->markTestSkipped('WooCommerce is not loaded.');
        }

        $user = get_userdata(self::factory()->user->create(['role' => 'customer']));
        $_POST['password_1'] = self::STRONG_PASSWORD;
        $errors = new WP_Error;

        do_action('validate_password_reset', $errors, $user);

        $this->assertFalse($errors->has_errors());
    }
}
