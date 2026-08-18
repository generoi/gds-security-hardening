<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;

/**
 * Do not advertise the WordPress version.
 */
class Version implements Module
{
    public function register(): void
    {
        add_filter('the_generator', '__return_empty_string');
        add_filter('script_loader_src', [$this, 'stripVersion']);
        add_filter('style_loader_src', [$this, 'stripVersion']);
    }

    /**
     * Replace ?ver=<wp_version> on assets registered without an explicit version.
     *
     * The replacement still has to change when WordPress does, or every asset
     * would stay cached across a core upgrade — but it must not be computable by
     * anyone else. wp_hash() keys on the site's own salts, so the token is stable
     * per site, changes with the core version, and tells an outsider nothing.
     *
     * Typed loosely on purpose: core passes `false` for a handle registered
     * without a src, and a third-party filter earlier in the chain can pass
     * anything at all.
     *
     * @param  mixed  $src
     * @return mixed
     */
    public function stripVersion($src)
    {
        if (! is_string($src) || $src === '') {
            return $src;
        }

        global $wp_version;

        parse_str((string) parse_url($src, PHP_URL_QUERY), $query);

        if (! empty($query['ver']) && $query['ver'] === $wp_version) {
            $src = add_query_arg('ver', substr(wp_hash($wp_version), 0, 12), $src);
        }

        return $src;
    }
}
