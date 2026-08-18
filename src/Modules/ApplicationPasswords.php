<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;
use WP_User;

class ApplicationPasswords implements Module
{
    public function register(): void
    {
        add_action('load-authorize-application.php', [$this, 'refuseAuthorizationScreen']);
        add_filter('wp_is_application_passwords_available_for_user', [$this, 'availableForUser'], 10, 2);
    }

    /**
     * Close the remote application authorization flow.
     *
     * wp-admin/authorize-application.php lets a third party link in with a
     * `success_url`, have the logged-in user press Approve, and receive a freshly
     * minted Application Password on the redirect — which core sends with
     * wp_redirect() rather than wp_safe_redirect(), deliberately, so the password
     * can be handed to an arbitrary domain.
     *
     * The Approve button is a same-origin DOM node in an authenticated session,
     * so it is pressable without ever reading the page. Passwords created by hand
     * under Users > Profile are a separate screen and keep working.
     */
    public function refuseAuthorizationScreen(): void
    {
        wp_die(
            __('Remote application authorization is disabled on this site. Create an application password from your profile instead.', 'wp-security-hardening'),
            __('Authorization disabled', 'wp-security-hardening'),
            ['response' => 403, 'back_link' => true],
        );
    }

    /**
     * Keep Application Passwords to accounts holding manage_options.
     *
     * Core applies no role check at all — wp_is_application_passwords_supported()
     * is `is_ssl() || 'local' === wp_get_environment_type()` — so any account that
     * can reach the admin can otherwise mint a credential that survives a password
     * reset and bypasses two-factor.
     *
     * Deliberately not user_can(). This filter runs inside
     * wp_validate_application_password(), hooked on determine_current_user, so the
     * current user is still being resolved. A capability check re-enters that
     * resolution through any user_has_cap or map_meta_cap callback that consults
     * the current user — two-factor and role-editing plugins routinely hook both —
     * and wp_get_current_user() has no reentrancy guard, so it recurses until PHP
     * runs out of memory.
     *
     * allcaps avoids the pipeline while keeping capability semantics: it is built
     * by WP_User::get_role_caps(), which applies no filters. user_has_cap is
     * applied in has_cap(), which is the part that must not be reached.
     *
     * A site with an integration user below this bar widens it from its own
     * mu-plugins at a later priority rather than forking this package.
     *
     * @param  bool  $available
     * @param  WP_User  $user
     */
    public function availableForUser($available, $user): bool
    {
        if (! $available) {
            return (bool) $available;
        }

        $user = $user instanceof WP_User ? $user : get_userdata($user);

        if (! $user || ! $user->exists()) {
            return false;
        }

        if (! empty($user->allcaps['manage_options'])) {
            return true;
        }

        // is_super_admin() is only safe behind is_multisite(): on single site it
        // falls through to $user->has_cap('delete_users') — the pipeline again.
        return is_multisite() && is_super_admin($user->ID);
    }
}
