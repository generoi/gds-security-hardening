<?php

namespace GeneroWP\SecurityHardening;

use GeneroWP\SecurityHardening\Modules\ApplicationPasswords;
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
     * Every module is unconditional and takes no configuration. Anything that
     * needs a per-site answer belongs in that site's own mu-plugins, widening
     * one of these from a later priority — see the README.
     *
     * @return class-string<Module>[]
     */
    public const MODULES = [
        XmlRpc::class,
        Rest::class,
        ApplicationPasswords::class,
        Headers::class,
        Uploads::class,
        UserEnumeration::class,
        Passwords::class,
        Roles::class,
        Version::class,
        Filesystem::class,
    ];

    public static function boot(): void
    {
        foreach (self::MODULES as $module) {
            (new $module)->register();
        }
    }
}
