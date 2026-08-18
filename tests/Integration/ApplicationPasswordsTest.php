<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use WP_UnitTestCase;

class ApplicationPasswordsTest extends WP_UnitTestCase
{
    protected function available(int $userId): bool
    {
        // Assert on the filter rather than on
        // wp_is_application_passwords_available_for_user(): core's own
        // is_ssl() precondition short-circuits under CLI and returns false
        // regardless of any filter, which will mislead you.
        return (bool) apply_filters(
            'wp_is_application_passwords_available_for_user',
            true,
            get_userdata($userId),
        );
    }

    public function test_an_administrator_is_allowed(): void
    {
        $this->assertTrue($this->available(self::factory()->user->create(['role' => 'administrator'])));
    }

    public function test_an_editor_is_refused(): void
    {
        $this->assertFalse($this->available(self::factory()->user->create(['role' => 'editor'])));
    }

    public function test_a_subscriber_is_refused(): void
    {
        $this->assertFalse($this->available(self::factory()->user->create(['role' => 'subscriber'])));
    }

    /**
     * An "owner" role cloned from administrator is a normal pattern, and a bare
     * administrator-role check would wrongly refuse it. The gate is on the
     * capability.
     */
    public function test_a_custom_role_with_manage_options_is_allowed(): void
    {
        add_role('owner', 'Owner', get_role('administrator')->capabilities);
        $user = self::factory()->user->create(['role' => 'owner']);

        $allowed = $this->available($user);
        remove_role('owner');

        $this->assertTrue($allowed);
    }

    /**
     * The filter runs inside wp_validate_application_password(), hooked on
     * determine_current_user, so the current user is still being resolved. A
     * capability check re-enters that resolution through any user_has_cap
     * callback that consults the current user — two-factor and role-editing
     * plugins routinely hook exactly this — and wp_get_current_user() has no
     * reentrancy guard, so a capability check here exhausts memory.
     */
    public function test_it_does_not_recurse_when_a_plugin_hooks_user_has_cap(): void
    {
        $callback = function ($allcaps) {
            current_user_can('read');

            return $allcaps;
        };
        add_filter('user_has_cap', $callback, 0);

        $allowed = $this->available(self::factory()->user->create(['role' => 'administrator']));

        remove_filter('user_has_cap', $callback, 0);

        $this->assertTrue($allowed);
    }
}
