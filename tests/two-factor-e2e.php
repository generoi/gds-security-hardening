<?php

/*
Plugin Name:  Two-factor enforcement for e2e
Description:  Turns the opt-in TwoFactor module on while tests/e2e/two-factor.spec.js runs
Version:      1.0.0
*/

use GeneroWP\SecurityHardening\Modules\TwoFactor;
use GeneroWP\SecurityHardening\Plugin;

/*
 * TwoFactor is opt-in, so nothing else in either wp-env site runs with it.
 *
 * It switches on only while two-factor.spec.js has set this option. wp-env
 * mounts mu-plugins into the PHPUnit site as well, and TwoFactorTest registers
 * the module itself; a second copy registered here would make those tests pass
 * or fail for the wrong reason.
 *
 * Even then it applies only to accounts carrying the meta, so the admin every
 * other spec logs in as is never put behind enrolment.
 */
const GDS_E2E_REQUIRE_TWO_FACTOR = 'gds_e2e_require_two_factor';

if (! get_option(GDS_E2E_REQUIRE_TWO_FACTOR)) {
    return;
}

add_filter(Plugin::FILTER_MODULES, fn (array $modules) => [...$modules, TwoFactor::class]);

add_filter(
    TwoFactor::FILTER_REQUIRED,
    fn (bool $required, WP_User $user) => $required && get_user_meta($user->ID, GDS_E2E_REQUIRE_TWO_FACTOR, true),
    10,
    2,
);
