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

    /**
     * Filters whether the current user has to enrol at all.
     *
     * Every logged-in user by default. A site with customer accounts or an
     * integration user narrows it — a WooCommerce customer stripped to `read`
     * loses view_order and pay_for_order, and a service account cannot scan a QR
     * code:
     *
     *     add_filter(TwoFactor::FILTER_REQUIRED, fn (bool $required, WP_User $user) =>
     *         $required && in_array('administrator', $user->roles, true)
     *     , 10, 2);
     *
     * Runs inside the capability pipeline, so decide from the user object —
     * $user->roles, is_super_admin() — never current_user_can() or user_can(). A
     * capability check here is answered with the reentrancy guard still up, which
     * fails open, so it reports capabilities the user may not keep.
     */
    public const FILTER_REQUIRED = 'gds_security_hardening_two_factor_required';

    /**
     * Guards against re-entering the capability pipeline from inside it.
     */
    protected static bool $resolving = false;

    public function register(): void
    {
        add_action('admin_init', [$this, 'redirectToEnrolment']);
        add_action('admin_page_access_denied', [$this, 'redirectToEnrolment']);
        add_action('admin_notices', [$this, 'explainTheRestriction']);
        add_filter('user_has_cap', [$this, 'stripCapabilities'], 0, 4);
        add_filter('map_meta_cap', [$this, 'stripMetaCapabilities'], 0, 4);
        add_filter('woocommerce_prevent_admin_access', [$this, 'letEnrolmentPastWooCommerce']);
    }

    /**
     * Let an unenrolled user past WooCommerce's wp-admin gate.
     *
     * WC_Admin::prevent_admin_access() sends anyone without edit_posts,
     * manage_woocommerce or view_admin_dashboard to My Account, and this module
     * has just stripped all three. profile.php, where the user enrols, became
     * unreachable: they landed on /my-account/#two-factor-options with no way
     * forward. redirectToEnrolment() still sends them from every other admin
     * page to their profile, so this opens nothing but enrolment.
     *
     * A user the site exempts through FILTER_REQUIRED, such as a customer,
     * counts as enrolled, so WooCommerce keeps them out of wp-admin as before.
     */
    public function letEnrolmentPastWooCommerce(bool $prevent): bool
    {
        return $prevent && $this->isEnrolled();
    }

    /**
     * Whether the current user has two-factor set up, or is exempt from it
     * through FILTER_REQUIRED.
     *
     * Resolved outside the capability pipeline: the two-factor plugin's own
     * lookups check capabilities, so calling this from within map_meta_cap or
     * user_has_cap re-enters that pipeline from inside itself.
     *
     * Two guards, for two different ways in.
     *
     * _wp_get_current_user() has no reentrancy guard (wp-includes/user.php):
     * while $current_user is still empty it re-enters
     * `apply_filters('determine_current_user', false)` every time it is called.
     * When the user is not resolved yet there is nobody to enforce against, so
     * this reports enrolled and leaves the caps alone.
     *
     * The static flag covers the commoner case, which the empty check does not:
     * once the user *is* resolved, this still runs from inside map_meta_cap, and
     * other callbacks on that same filter perform capability checks of their own.
     * WooCommerce's wc_modify_map_meta_cap() calls wc_current_user_has_role(),
     * and two-factor's own provider lookups check capabilities — so without the
     * flag, map_meta_cap re-enters map_meta_cap until PHP runs out of memory.
     * Measured: a 1GB limit exhausted after four tests once WooCommerce was
     * loaded.
     *
     * Failing open while resolving is the safe direction. Enforcement happens on
     * the outer check, which completes normally.
     *
     * @see https://github.com/Automattic/vip-go-mu-plugins/blob/develop/two-factor.php
     */
    public function isEnrolled(): bool
    {
        if (empty($GLOBALS['current_user']) || self::$resolving) {
            return true;
        }

        self::$resolving = true;

        try {
            if (! is_user_logged_in()) {
                return false;
            }

            if (! class_exists(Two_Factor_Core::class)) {
                return true;
            }

            if (! apply_filters(self::FILTER_REQUIRED, true, wp_get_current_user())) {
                return true;
            }

            return Two_Factor_Core::is_user_using_two_factor();
        } finally {
            self::$resolving = false;
        }
    }

    /**
     * Send an unenrolled user to the one screen they can use.
     *
     * Hooked twice, because admin_init alone comes too late for most screens.
     * wp-admin/admin.php requires menu.php before firing admin_init, and menu.php
     * ends with core's own page access check: a screen the stripped user may not
     * open, such as edit.php, wp_die()s there with "Sorry, you are not allowed to
     * access this page." admin_page_access_denied fires just before that die.
     * admin_init still covers the screens that pass the check, like the
     * dashboard.
     */
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
     * Say why the account is restricted.
     *
     * Without this the user is redirected to their profile with no explanation,
     * and everything else they try silently fails — which reads as a broken site
     * rather than a policy.
     */
    public function explainTheRestriction(): void
    {
        if ($this->isEnrolled()) {
            return;
        }

        printf(
            '<div class="notice notice-error"><p>%s</p></div>',
            esc_html__(
                'Two-factor authentication is required on this site. Set it up below to restore access.',
                'gds-security-hardening',
            ),
        );
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

        /*
         * Leave core's self-edit allowance alone.
         *
         * map_meta_cap breaks with $caps still empty for a user editing
         * themselves (capabilities.php:70), and empty means allowed. Replacing
         * that with do_not_allow makes wp-admin/user-edit.php:194 wp_die() on
         * profile.php, and 403s two-factor's own REST enrolment route, whose
         * permission callback starts with current_user_can('edit_user').
         *
         * An unenrolled user would then have no way to enrol — locked out by the
         * control that exists to make them enrol. `read` alone is not enough to
         * reach the profile screen.
         */
        if ($cap === 'edit_user' && isset($args[0]) && $userId === (int) $args[0]) {
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
