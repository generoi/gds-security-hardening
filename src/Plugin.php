<?php

namespace GeneroWP\SecurityHardening;

use GeneroWP\SecurityHardening\Modules\ApplicationPasswords;
use GeneroWP\SecurityHardening\Modules\ContentSecurityPolicy;
use GeneroWP\SecurityHardening\Modules\Filesystem;
use GeneroWP\SecurityHardening\Modules\Headers;
use GeneroWP\SecurityHardening\Modules\Passwords;
use GeneroWP\SecurityHardening\Modules\Rest;
use GeneroWP\SecurityHardening\Modules\Roles;
use GeneroWP\SecurityHardening\Modules\Uploads;
use GeneroWP\SecurityHardening\Modules\UserEnumeration;
use GeneroWP\SecurityHardening\Modules\Version;
use GeneroWP\SecurityHardening\Modules\XmlRpc;

class Plugin
{
    /**
     * Every module here is unconditional and takes no configuration. Anything
     * that needs a per-site answer belongs in that site's own mu-plugins,
     * widening one of these from a later priority — see the README.
     *
     * Modules that exist but are not listed are opt-in, added through the same
     * filter that removes one. TwoFactor is the current example: it needs the
     * two-factor plugin and locks every account out until they enrol, which is a
     * decision a site makes rather than one a package makes for it.
     *
     * @return class-string<Module>[]
     */
    public const MODULES = [
        XmlRpc::class,
        Rest::class,
        ApplicationPasswords::class,
        Headers::class,
        ContentSecurityPolicy::class,
        Uploads::class,
        UserEnumeration::class,
        Passwords::class,
        Roles::class,
        Version::class,
        Filesystem::class,
    ];

    public const FILTER_MODULES = 'gds_security_hardening_modules';

    public static function boot(): void
    {
        /**
         * Filters the modules that will be registered.
         *
         * The intended use is removal — a site that genuinely cannot live with
         * one control drops that class and keeps the rest, instead of forking the
         * package or disabling it wholesale:
         *
         *     add_filter('gds_security_hardening_modules', fn ($modules) => array_diff(
         *         $modules,
         *         [\GeneroWP\SecurityHardening\Modules\Uploads::class],
         *     ));
         *
         * Prefer widening the control itself from a later priority where that is
         * possible; removal is the blunter instrument.
         *
         * @param  class-string<Module>[]  $modules
         */
        $modules = apply_filters(self::FILTER_MODULES, self::MODULES);

        foreach ($modules as $module) {
            if (! is_subclass_of($module, Module::class)) {
                continue;
            }

            (new $module)->register();
        }
    }
}
