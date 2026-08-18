<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\Passwords;
use WP_Error;
use WP_REST_Request;
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

        $this->assertWPError($this->module->validateRestUser(new \stdClass, $request));
    }

    public function test_a_long_enough_rest_password_passes_through_untouched(): void
    {
        $request = new WP_REST_Request('POST', '/wp/v2/users');
        $request->set_param('password', str_repeat('a', 12));
        $prepared = new \stdClass;

        $this->assertSame($prepared, $this->module->validateRestUser($prepared, $request));
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
        $this->assertFalse((bool) username_exists('restshortpw'));
    }

    public function test_the_rest_users_route_accepts_a_long_enough_password(): void
    {
        wp_set_current_user(self::factory()->user->create(['role' => 'administrator']));

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
