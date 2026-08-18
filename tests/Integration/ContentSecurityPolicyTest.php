<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\ContentSecurityPolicy;
use GeneroWP\SecurityHardening\Modules\TwoFactor;
use GeneroWP\SecurityHardening\Plugin;
use WP_UnitTestCase;

class ContentSecurityPolicyTest extends WP_UnitTestCase
{
    public function test_the_policy_carries_only_directives_that_need_no_per_site_sweep(): void
    {
        $this->assertSame([
            "base-uri 'self'",
            "frame-ancestors 'self'",
            "object-src 'none'",
        ], ContentSecurityPolicy::DIRECTIVES);
    }

    /**
     * wp-admin cannot take a script policy without a per-site plugin sweep: core
     * prints un-nonced inline scripts on every screen and the media library needs
     * eval, so a nonce is out, and the nonce-free alternative blocks the external
     * script tags plugins legitimately use on their own screens.
     */
    public function test_the_shared_directives_say_nothing_about_scripts(): void
    {
        $policy = implode('; ', ContentSecurityPolicy::DIRECTIVES);

        $this->assertStringNotContainsString('script-src', $policy);
        $this->assertStringNotContainsString('default-src', $policy);
    }

    public function test_the_login_nonce_is_stable_within_a_request(): void
    {
        $module = new ContentSecurityPolicy;

        $this->assertSame($module->nonce(), $module->nonce());
        $this->assertNotSame($module->nonce(), (new ContentSecurityPolicy)->nonce());
    }

    /**
     * Every script tag has to carry the same nonce as the header, or the policy
     * blocks the login screen's own JavaScript.
     */
    public function test_script_tags_get_the_same_nonce_as_the_header(): void
    {
        $module = new ContentSecurityPolicy;

        $this->assertSame($module->nonce(), $module->addNonce([])['nonce']);
    }

    public function test_the_login_policy_locks_scripts_to_the_nonce(): void
    {
        $module = new ContentSecurityPolicy;
        $directives = [
            ...ContentSecurityPolicy::DIRECTIVES,
            ...ContentSecurityPolicy::LOGIN_DIRECTIVES,
            sprintf("script-src 'nonce-%s' 'strict-dynamic'", $module->nonce()),
        ];
        $policy = implode('; ', $directives);

        $this->assertStringContainsString("script-src 'nonce-", $policy);
        $this->assertStringContainsString("'strict-dynamic'", $policy);
        $this->assertStringNotContainsString("'unsafe-inline'", $policy);
        $this->assertStringContainsString("form-action 'self'", $policy);
    }

    public function test_the_directives_are_filterable(): void
    {
        $callback = fn (array $directives) => [...$directives, "form-action 'self'"];
        add_filter('wp_security_hardening_csp_directives', $callback);

        $directives = apply_filters('wp_security_hardening_csp_directives', ContentSecurityPolicy::DIRECTIVES);

        remove_filter('wp_security_hardening_csp_directives', $callback);

        $this->assertContains("form-action 'self'", $directives);
    }

    public function test_two_factor_is_not_registered_by_default(): void
    {
        $this->assertNotContains(TwoFactor::class, Plugin::MODULES);
    }

    public function test_the_content_security_policy_is_registered_by_default(): void
    {
        $this->assertContains(ContentSecurityPolicy::class, Plugin::MODULES);
    }

    /**
     * Without the two-factor plugin the module must be inert: locking every
     * account out of a site that has no way to enrol is worse than not enforcing.
     */
    public function test_two_factor_is_inert_without_the_plugin(): void
    {
        if (class_exists(\Two_Factor_Core::class)) {
            $this->markTestSkipped('two-factor is installed in this environment.');
        }

        wp_set_current_user(self::factory()->user->create(['role' => 'administrator']));

        $this->assertTrue((new TwoFactor)->isEnrolled());
    }

    public function test_the_modules_filter_can_remove_a_module(): void
    {
        $callback = fn (array $modules) => array_values(array_diff($modules, [ContentSecurityPolicy::class]));
        add_filter(Plugin::FILTER_MODULES, $callback);

        $modules = apply_filters(Plugin::FILTER_MODULES, Plugin::MODULES);

        remove_filter(Plugin::FILTER_MODULES, $callback);

        $this->assertNotContains(ContentSecurityPolicy::class, $modules);
    }
}
