<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\Headers;
use GeneroWP\SecurityHardening\Modules\UserEnumeration;
use WP_Error;
use WP_UnitTestCase;

class HeadersTest extends WP_UnitTestCase
{
    /**
     * Core deliberately does not send X-Frame-Options on the frontend: a site may
     * legitimately be embedded elsewhere. Asserting it there breaks those embeds.
     */
    public function test_x_frame_options_is_not_asserted_on_the_frontend(): void
    {
        $this->assertArrayNotHasKey('X-Frame-Options', Headers::HEADERS);
        $this->assertArrayHasKey('X-Frame-Options', Headers::PRIVILEGED_HEADERS);
    }

    public function test_the_always_on_headers_are_safe_everywhere(): void
    {
        $this->assertSame('nosniff', Headers::HEADERS['X-Content-Type-Options']);
        $this->assertSame('strict-origin-when-cross-origin', Headers::HEADERS['Referrer-Policy']);
    }

    /**
     * HSTS is meaningless over plain http and would break a local environment, so
     * it is conditional rather than a constant in the always-on list.
     */
    public function test_hsts_is_not_in_the_unconditional_list(): void
    {
        $this->assertArrayNotHasKey('Strict-Transport-Security', Headers::HEADERS);
        $this->assertStringContainsString('max-age=', Headers::STRICT_TRANSPORT_SECURITY);
    }

    public function test_the_headers_are_filterable(): void
    {
        $callback = fn (array $headers) => [...$headers, 'X-Test' => 'value'];
        add_filter('gds_security_hardening_headers', $callback);

        $filtered = apply_filters('gds_security_hardening_headers', Headers::HEADERS, false);

        remove_filter('gds_security_hardening_headers', $callback);

        $this->assertSame('value', $filtered['X-Test']);
    }

    /**
     * wp-login.php applies lost_password on the plain GET of the form too, and it
     * populates the errors from $_GET['error'] first. Redirecting there sends a
     * user who clicked an expired reset link to checkemail=confirm, where they can
     * never request a new one.
     */
    public function test_an_expired_reset_link_is_not_redirected_away(): void
    {
        $module = new UserEnumeration;
        $errors = new WP_Error('expiredkey', 'Your password reset link has expired.');

        $_POST = [];
        $module->alwaysRedirectLostPassword($errors);

        // Reaching here at all is the assertion: the redirect calls exit.
        $this->assertContains('expiredkey', $errors->get_error_codes());
    }

    public function test_a_plain_get_of_the_form_is_not_redirected_away(): void
    {
        $module = new UserEnumeration;
        $errors = new WP_Error('invalid_email', 'There is no account with that username or email address.');

        $_POST = [];
        $module->alwaysRedirectLostPassword($errors);

        $this->assertTrue($errors->has_errors());
    }
}
