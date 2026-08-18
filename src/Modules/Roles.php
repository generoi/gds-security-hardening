<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;

/**
 * Pin default_role.
 *
 * The post-exploitation step of nearly every privilege-escalation chain is the
 * same: open registration, set default_role to administrator, register. Pinning
 * the role kills it — registration being on then buys an attacker a subscriber.
 *
 * default_role is an option rather than a constant, so it cannot be pinned from
 * wp-config the way DISALLOW_FILE_MODS is; there is no WP_DEFAULT_ROLE.
 * pre_option_default_role short-circuits the read, which makes the stored value
 * irrelevant whatever manages to write to it.
 *
 * WooCommerce is unaffected: wc_create_new_customer() passes 'customer'
 * explicitly and never consults this.
 *
 * Known cost: Settings > General still shows the "New User Default Role"
 * dropdown and saving it now has no effect. Deliberate — the field has no
 * legitimate use and every illegitimate one.
 *
 * users_can_register is deliberately not pinned. It buys nothing where
 * self-registration actually happens, because WooCommerce gates registration on
 * its own options and never reads it, and it is per-site policy rather than a
 * primitive nobody uses.
 */
class Roles implements Module
{
    public const DEFAULT_ROLE = 'subscriber';

    public function register(): void
    {
        add_filter('pre_option_default_role', [$this, 'defaultRole']);
    }

    public function defaultRole(): string
    {
        return self::DEFAULT_ROLE;
    }
}
