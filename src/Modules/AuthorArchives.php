<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;
use WP_Sitemaps_Provider;

/**
 * Close author archives, and the sitemaps that list them.
 *
 * /author/<nicename>/ is a login-name oracle: an existing name answers and an
 * unknown one 404s, and the sitemaps hand out the full list without guessing.
 * Our sites do not use author archives, so they are closed outright. A site that
 * does removes this module with the modules filter; UserEnumeration still closes
 * `?author=<id>` for it.
 */
class AuthorArchives implements Module
{
    public function register(): void
    {
        add_filter('request', [$this, 'notFound']);
        add_filter('wp_sitemaps_add_provider', [$this, 'dropUsersSitemap'], 10, 2);
        add_filter('wpseo_sitemap_exclude_author', '__return_empty_array');
    }

    /**
     * Turn every author request into a 404, whether or not the user exists.
     *
     * Rewritten at `request`, on the parsed query vars, rather than by testing
     * is_author() later. That catches the pretty URL, `?author=N` and
     * `?author_name=` alike, including a percent-encoded key or a POST body that a
     * QUERY_STRING check misses. It also runs before redirect_canonical() and
     * Yoast's archive redirect, both of which 301 an existing name — and only an
     * existing one — so a 404 decided after them would still leave the oracle.
     *
     * REST requests keep their query vars: `/wp-json/wp/v2/posts?author=N` is a
     * collection filter, not an archive.
     *
     * @param  array<string, mixed>  $queryVars
     * @return array<string, mixed>
     */
    public function notFound(array $queryVars): array
    {
        if (isset($queryVars['rest_route'])) {
            return $queryVars;
        }

        if (isset($queryVars['author']) || isset($queryVars['author_name'])) {
            return ['error' => '404'];
        }

        return $queryVars;
    }

    /**
     * Drop core's wp-sitemap-users-*.xml, which lists the archive of every user
     * with published posts. The other providers are unaffected.
     */
    public function dropUsersSitemap(WP_Sitemaps_Provider|false $provider, string $name): WP_Sitemaps_Provider|false
    {
        return $name === 'users' ? false : $provider;
    }
}
