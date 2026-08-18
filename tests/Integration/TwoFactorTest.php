<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\TwoFactor;
use WP_UnitTestCase;

class TwoFactorTest extends WP_UnitTestCase
{
    protected TwoFactor $module;

    protected int $user;

    public function set_up(): void
    {
        parent::set_up();

        // Methods are called directly rather than through register(): hooking
        // them here would leave the filters attached for the rest of the suite.
        //
        // isEnrolled() is overridden because the two-factor plugin is not loaded
        // by the phpunit bootstrap — without it the module reports enrolled by
        // design, so the unenrolled branch would never be exercised.
        $this->module = new class extends TwoFactor
        {
            public bool $enrolled = false;

            public function isEnrolled(): bool
            {
                return $this->enrolled;
            }
        };
        $this->user = self::factory()->user->create(['role' => 'administrator']);
        wp_set_current_user($this->user);
    }

    /**
     * The defect this test exists for.
     *
     * map_meta_cap returning an empty array denies nothing. WP_User::has_cap()
     * ends with `foreach ((array) $caps as $cap) { ... } return true;`, so an
     * empty array skips the loop and grants. An unenrolled user was therefore
     * given *every* capability — manage_options, edit_users, install_plugins —
     * the exact inverse of this module's purpose.
     */
    public function test_an_unenrolled_user_is_denied_rather_than_granted(): void
    {
        $caps = $this->module->stripMetaCapabilities(['manage_options'], 'manage_options', $this->user, []);

        $this->assertNotSame([], $caps, 'An empty caps array grants the capability.');
        $this->assertSame(['do_not_allow'], $caps);
    }

    public function test_read_stays_allowed_so_the_profile_screen_is_reachable(): void
    {
        $this->assertSame(
            ['read'],
            $this->module->stripMetaCapabilities(['read'], 'read', $this->user, []),
        );
    }

    public function test_an_unenrolled_user_keeps_only_read_in_allcaps(): void
    {
        $stripped = $this->module->stripCapabilities(
            ['read' => true, 'manage_options' => true, 'edit_users' => true],
            ['manage_options'],
            [],
            $this->user,
        );

        $this->assertSame(['read' => true], $stripped);
    }

    /**
     * Core's own semantics, asserted directly so the reasoning above cannot
     * quietly stop being true under a future WordPress.
     */
    public function test_core_grants_on_an_empty_caps_array_and_denies_on_do_not_allow(): void
    {
        $user = get_userdata($this->user);

        $granting = fn () => [];
        add_filter('map_meta_cap', $granting, 99);
        $granted = $user->has_cap('some_made_up_capability');
        remove_filter('map_meta_cap', $granting, 99);

        $denying = fn () => ['do_not_allow'];
        add_filter('map_meta_cap', $denying, 99);
        $denied = $user->has_cap('some_made_up_capability');
        remove_filter('map_meta_cap', $denying, 99);

        $this->assertTrue($granted, 'Core grants when map_meta_cap returns [].');
        $this->assertFalse($denied, 'Core denies on do_not_allow.');
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

        $enrolled = (new TwoFactor)->isEnrolled();

        $GLOBALS['current_user'] = $previous;

        $this->assertTrue($enrolled);
    }

    public function test_an_enrolled_user_keeps_everything(): void
    {
        $this->module->enrolled = true;

        $this->assertSame(
            ['manage_options'],
            $this->module->stripMetaCapabilities(['manage_options'], 'manage_options', $this->user, []),
        );
    }
}
