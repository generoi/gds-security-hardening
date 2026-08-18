<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\TwoFactor;
use Two_Factor_Core;
use WP_UnitTestCase;

/**
 * Against the real two-factor plugin, loaded in tests/bootstrap.php.
 */
class TwoFactorTest extends WP_UnitTestCase
{
    protected TwoFactor $module;

    protected int $user;

    public function set_up(): void
    {
        parent::set_up();

        if (! class_exists(Two_Factor_Core::class)) {
            $this->markTestSkipped('The two-factor plugin is not loaded.');
        }

        $this->module = new TwoFactor;
        $this->module->register();

        $this->user = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($this->user);
    }

    public function tear_down(): void
    {
        remove_filter('user_has_cap', [$this->module, 'stripCapabilities'], 0);
        remove_filter('map_meta_cap', [$this->module, 'stripMetaCapabilities'], 0);
        remove_action('admin_init', [$this->module, 'redirectToEnrolment']);

        parent::tear_down();
    }

    protected function enrol(int $user): void
    {
        update_user_meta($user, '_two_factor_enabled_providers', ['Two_Factor_Email']);
        update_user_meta($user, '_two_factor_provider', 'Two_Factor_Email');
    }

    public function test_the_plugin_agrees_the_fixture_user_is_not_enrolled(): void
    {
        $this->assertFalse(Two_Factor_Core::is_user_using_two_factor($this->user));
        $this->assertFalse($this->module->isEnrolled());
    }

    /**
     * The whole point, asserted the way WordPress asks the question.
     *
     * This is what an empty map_meta_cap return got wrong: has_cap() ends with
     * `foreach ((array) $caps as $cap)` and returns true on an empty array, so
     * returning [] granted every capability instead of denying it.
     */
    public function test_an_unenrolled_administrator_cannot_do_anything_privileged(): void
    {
        $this->assertFalse(current_user_can('manage_options'));
        $this->assertFalse(current_user_can('edit_users'));
        $this->assertFalse(current_user_can('install_plugins'));
        $this->assertFalse(current_user_can('edit_posts'));
    }

    public function test_an_unenrolled_user_can_still_reach_their_profile(): void
    {
        $this->assertTrue(current_user_can('read'));
    }

    public function test_an_enrolled_administrator_is_unaffected(): void
    {
        $this->enrol($this->user);
        wp_set_current_user($this->user);

        $this->assertTrue(Two_Factor_Core::is_user_using_two_factor($this->user));
        $this->assertTrue(current_user_can('manage_options'));
        $this->assertTrue(current_user_can('edit_users'));
    }

    /**
     * isEnrolled() runs from inside user_has_cap and map_meta_cap, and
     * _wp_get_current_user() has no reentrancy guard while $current_user is
     * empty, so it must not ask for the current user in that window.
     */
    public function test_it_does_not_resolve_the_current_user_mid_resolution(): void
    {
        $previous = $GLOBALS['current_user'] ?? null;
        unset($GLOBALS['current_user']);

        $enrolled = $this->module->isEnrolled();

        $GLOBALS['current_user'] = $previous;

        $this->assertTrue($enrolled);
    }
}
