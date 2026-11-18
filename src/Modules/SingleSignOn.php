<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;
use WP_Error;
use WP_SAML_Auth;
use WP_Session_Tokens;
use WP_User;

/**
 * Let SAML single sign-on stand in for the password and the second factor.
 *
 * Off by default — it only means something next to the wp-saml-auth plugin and
 * an identity provider the site has configured, which is a site's decision.
 * Opt in with:
 *
 *     add_filter('gds_security_hardening_modules', fn ($modules) => [
 *         ...$modules,
 *         \GeneroWP\SecurityHardening\Modules\SingleSignOn::class,
 *     ]);
 *
 * Connecting to the identity provider stays with the site, through
 * wp-saml-auth's own `wp_saml_auth_option` filter. This module is the policy
 * around it, and takes no configuration:
 *
 * - An account can be marked as requiring single sign-on. It then cannot sign
 *   in with its password, an application password included, anywhere that
 *   calls wp_signon() — wp-login.php and WooCommerce's my-account form alike.
 * - A single sign-on login skips the two-factor plugin's challenge. The
 *   identity provider ran its own MFA, and asking again buys nothing.
 * - A session that started with single sign-on counts as enrolled for the
 *   TwoFactor module, so an administrator who never set up a WordPress
 *   authenticator keeps their capabilities.
 *
 * Without wp-saml-auth loaded this does nothing: an account marked as requiring
 * single sign-on falls back to its password rather than being locked out of a
 * site that has no other way in.
 */
class SingleSignOn implements Module
{
    /**
     * User meta marking an account as single sign-on only. Network-wide on
     * multisite, like the account itself.
     */
    public const REQUIRED_META = 'gds_security_hardening_sso_required';

    /**
     * Key stored in a session's information when it started with single
     * sign-on.
     */
    public const SESSION_KEY = 'gds_security_hardening_sso';

    /**
     * The user wp-saml-auth authenticated during this request, if any.
     *
     * Static because the plugin's own hooks only know the user, not the module
     * instance that registered on them.
     */
    protected static ?int $authenticated = null;

    public function register(): void
    {
        add_action('wp_saml_auth_existing_user_authenticated', [$this, 'rememberSingleSignOn']);
        add_action('wp_saml_auth_new_user_authenticated', [$this, 'rememberSingleSignOn']);

        /*
         * Priority 30: after core's password (20) and application password (20)
         * authenticators and after wp-saml-auth (21), so both a password and a
         * SAML response have resolved to a user. Before two-factor (31), so a
         * refused password login never reaches its challenge, and before
         * UserEnumeration (100), which leaves this code alone.
         */
        add_filter('authenticate', [$this, 'refusePasswordLogin'], 30);

        add_filter('two_factor_is_required_for_user', [$this, 'skipSecondFactor'], 10, 2);
        add_filter('attach_session_information', [$this, 'markSession'], 10, 2);
        add_filter(TwoFactor::FILTER_REQUIRED, [$this, 'exemptSingleSignOnSession'], 10, 2);

        add_action('edit_user_profile', [$this, 'renderSetting']);
        add_action('show_user_profile', [$this, 'renderSetting']);
        add_action('edit_user_profile_update', [$this, 'saveSetting']);
        add_action('personal_options_update', [$this, 'saveSetting']);
    }

    public static function isAvailable(): bool
    {
        return class_exists(WP_SAML_Auth::class);
    }

    public static function isRequiredFor(int $userId): bool
    {
        return (bool) get_user_meta($userId, self::REQUIRED_META, true);
    }

    public function rememberSingleSignOn(WP_User $user): void
    {
        self::$authenticated = $user->ID;
    }

    public function authenticatedThisRequest(int $userId): bool
    {
        return self::$authenticated === $userId;
    }

    /**
     * @param  mixed  $user  WP_User, WP_Error or null
     */
    public function refusePasswordLogin(mixed $user): mixed
    {
        if (! $user instanceof WP_User || ! static::isAvailable()) {
            return $user;
        }

        if (! self::isRequiredFor($user->ID) || $this->authenticatedThisRequest($user->ID)) {
            return $user;
        }

        return new WP_Error(
            'gds_security_hardening_sso_required',
            __('<strong>Error:</strong> This account signs in with single sign-on.', 'gds-security-hardening'),
        );
    }

    /**
     * Skip two-factor's challenge for the login wp-saml-auth just completed.
     *
     * Only that user, only this request: a later password login by the same
     * account still gets the challenge.
     */
    public function skipSecondFactor(bool $required, WP_User $user): bool
    {
        return $required && ! $this->authenticatedThisRequest($user->ID);
    }

    /**
     * Remember in the session itself that it started with single sign-on.
     *
     * wp_set_auth_cookie() creates the session token inside wp_signon(), after
     * wp-saml-auth has run, so the flag set above is already in place.
     *
     * @param  array<string, mixed>  $session
     * @return array<string, mixed>
     */
    public function markSession(array $session, int $userId): array
    {
        if ($this->authenticatedThisRequest($userId)) {
            $session[self::SESSION_KEY] = true;
        }

        return $session;
    }

    /**
     * A single sign-on session has had its second factor, from the identity
     * provider, so the TwoFactor module should not strip it.
     *
     * Runs inside the capability pipeline, like every FILTER_REQUIRED callback.
     * Reading the session token and the session from user meta checks no
     * capabilities.
     */
    public function exemptSingleSignOnSession(bool $required, WP_User $user): bool
    {
        return $required && ! $this->isSingleSignOnSession($user);
    }

    public function isSingleSignOnSession(WP_User $user): bool
    {
        $token = wp_get_session_token();

        if ($token === '') {
            return false;
        }

        $session = WP_Session_Tokens::get_instance($user->ID)->get($token);

        return ! empty($session[self::SESSION_KEY]);
    }

    /**
     * Only for someone who may manage other accounts. On multisite edit_users
     * is a super admin capability, so a site administrator cannot change it.
     */
    public function renderSetting(WP_User $user): void
    {
        if (! static::isAvailable() || ! current_user_can('edit_users')) {
            return;
        }

        printf(
            '<h2>%s</h2><table class="form-table" role="presentation"><tr><th scope="row">%s</th><td><label><input type="checkbox" name="%s" value="1" %s> %s</label></td></tr></table>',
            esc_html__('Single sign-on', 'gds-security-hardening'),
            esc_html__('Require single sign-on', 'gds-security-hardening'),
            esc_attr(self::REQUIRED_META),
            checked(self::isRequiredFor($user->ID), true, false),
            esc_html__('Refuse this account’s password and application passwords.', 'gds-security-hardening'),
        );
    }

    /**
     * Core has checked the profile nonce and edit_user by the time these hooks
     * fire.
     *
     * Turning it on signs the account out everywhere else, so a session opened
     * with the password does not outlive the change. Not the session doing the
     * editing: an administrator marking their own account keeps working.
     */
    public function saveSetting(int $userId): void
    {
        if (! static::isAvailable() || ! current_user_can('edit_users')) {
            return;
        }

        $required = ! empty($_POST[self::REQUIRED_META]);

        if ($required === self::isRequiredFor($userId)) {
            return;
        }

        if (! $required) {
            delete_user_meta($userId, self::REQUIRED_META);

            return;
        }

        update_user_meta($userId, self::REQUIRED_META, '1');

        $sessions = WP_Session_Tokens::get_instance($userId);

        if ($userId === get_current_user_id()) {
            $sessions->destroy_others(wp_get_session_token());
        } else {
            $sessions->destroy_all();
        }
    }
}
