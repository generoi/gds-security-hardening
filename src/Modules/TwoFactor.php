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
 *     add_filter('wp_security_hardening_modules', fn ($modules) => [
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
     * Resolved once, outside the capability filters.
     *
     * Calling this from inside map_meta_cap or user_has_cap would re-enter the
     * capability pipeline from within itself.
     *
     * @see https://github.com/Automattic/vip-go-mu-plugins/blob/develop/two-factor.php
     */
    public function isEnrolled(): bool
    {
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

        return [];
    }
}
