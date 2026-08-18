<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;
use Two_Factor_Core;

/**
 * Require two-factor authentication to use the admin.
 *
 * Off by default — it needs the two-factor plugin and it locks every account out
 * of everything until they enrol, which is a decision a site makes rather than
 * one a package makes for it. Opt in with:
 *
 *     add_filter('gds_security_hardening_modules', fn ($modules) => [
 *         ...$modules,
 *         \GeneroWP\SecurityHardening\Modules\TwoFactor::class,
 *     ]);
 *
 * Without the two-factor plugin active this does nothing, rather than locking
 * everyone out of a site that has no way to enrol.
 */
class TwoFactor implements Module
{
    /**
     * The one capability an unenrolled user keeps, so they can reach their
     * profile and set two-factor up.
     */
    public const ALLOWED_CAPABILITY = 'read';

    public function register(): void
    {
        add_action('admin_init', [$this, 'redirectToEnrolment']);
        add_filter('user_has_cap', [$this, 'stripCapabilities'], 0, 4);
        add_filter('map_meta_cap', [$this, 'stripMetaCapabilities'], 0, 4);
    }

    /**
     * Whether the current user has two-factor set up.
     *
     * Resolved outside the capability pipeline: the two-factor plugin's own
     * lookups check capabilities, so calling this from within map_meta_cap or
     * user_has_cap re-enters that pipeline from inside itself.
     *
     * The first guard matters more than it looks. _wp_get_current_user() has no
     * reentrancy guard (wp-includes/user.php): while $current_user is still empty
     * it re-enters `apply_filters('determine_current_user', false)` every time it
     * is called. So if any plugin performs a capability check during that
     * resolution — which is exactly what a user_has_cap callback would do here —
     * asking for the current user recurses until PHP runs out of memory. When the
     * user is not resolved yet there is nobody to enforce against, so this
     * reports enrolled and leaves the caps alone; enforcement happens on the
     * checks that come after resolution.
     *
     * @see https://github.com/Automattic/vip-go-mu-plugins/blob/develop/two-factor.php
     */
    public function isEnrolled(): bool
    {
        if (empty($GLOBALS['current_user'])) {
            return true;
        }

        if (! is_user_logged_in()) {
            return false;
        }

        if (! class_exists(Two_Factor_Core::class)) {
            return true;
        }

        return Two_Factor_Core::is_user_using_two_factor();
    }

    public function redirectToEnrolment(): void
    {
        global $pagenow;

        // profile.php is where two-factor is set up, so it has to stay reachable.
        if ($pagenow === 'profile.php' || wp_doing_ajax() || $this->isEnrolled()) {
            return;
        }

        wp_safe_redirect(admin_url('profile.php#two-factor-options'));
        exit;
    }

    /**
     * @param  array<string, bool>  $allcaps
     * @param  string[]  $caps
     * @param  array<int, mixed>  $args
     * @return array<string, bool>
     */
    public function stripCapabilities(array $allcaps, array $caps, array $args, mixed $user): array
    {
        if ($this->isEnrolled()) {
            return $allcaps;
        }

        return array_intersect_key($allcaps, [self::ALLOWED_CAPABILITY => true]);
    }

    /**
     * @param  string[]  $caps
     * @param  array<int, mixed>  $args
     * @return string[]
     */
    public function stripMetaCapabilities(array $caps, string $cap, int $userId, array $args): array
    {
        if ($this->isEnrolled() || $cap === self::ALLOWED_CAPABILITY) {
            return $caps;
        }

        // 'do_not_allow', never an empty array. WP_User::has_cap() ends with
        //
        //     foreach ( (array) $caps as $cap ) {
        //         if ( empty( $capabilities[ $cap ] ) ) { return false; }
        //     }
        //     return true;
        //
        // so an empty $caps skips the loop and returns *true* — returning []
        // here grants every capability instead of denying it, which is the exact
        // inverse of this module. Core unsets 'do_not_allow' from $capabilities
        // just above that loop, so requiring it always fails.
        return ['do_not_allow'];
    }
}
