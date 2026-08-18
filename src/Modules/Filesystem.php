<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;

/**
 * Keep WordPress out of files the web server executes.
 *
 * Same family as DISALLOW_FILE_MODS, which belongs in wp-config rather than
 * here: this takes .htaccess out of WordPress's reach.
 */
class Filesystem implements Module
{
    public function register(): void
    {
        add_filter('flush_rewrite_rules_hard', '__return_false', 99);
    }
}
