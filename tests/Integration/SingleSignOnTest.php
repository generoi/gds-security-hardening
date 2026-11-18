<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\SingleSignOn;
use GeneroWP\SecurityHardening\Modules\TwoFactor;
use Two_Factor_Core;
use WP_Error;
use WP_SAML_Auth;
use WP_Session_Tokens;
use WP_UnitTestCase;
use WP_User;

/**
 * Against the real two-factor and wp-saml-auth plugins, loaded in
 * tests/bootstrap.php.
 *
 * A SAML login is simulated by firing wp-saml-auth's own
 * wp_saml_auth_existing_user_authenticated action, which is what its
 * authenticate callback does once a response validates. Validating a signed
 * response is the plugin's job, not this module's.
 */
class SingleSignOnTest extends WP_UnitTestCase
{
    protected SingleSignOn $module;

    protected WP_User $user;

    protected ?TwoFactor $twoFactor = null;

    public function set_up(): void
    {
        parent::set_up();

        if (! class_exists(WP_SAML_Auth::class) || ! class_exists(Two_Factor_Core::class)) {
            $this->markTestSkipped('wp-saml-auth or two-factor is not loaded.');
        }

        $this->module = new SingleSignOn;
        $this->module->register();

        $this->user = self::factory()->user->create_and_get(['role' => 'administrator']);
    }

    public function tear_down(): void
    {
        $this->forgetSingleSignOn();

        remove_action('wp_saml_auth_existing_user_authenticated', [$this->module, 'rememberSingleSignOn']);
        remove_action('wp_saml_auth_new_user_authenticated', [$this->module, 'rememberSingleSignOn']);
        remove_filter('authenticate', [$this->module, 'refusePasswordLogin'], 30);
        remove_filter('two_factor_is_required_for_user', [$this->module, 'skipSecondFactor']);
        remove_filter('attach_session_information', [$this->module, 'markSession']);
        remove_all_filters(TwoFactor::FILTER_REQUIRED);

        if ($this->twoFactor) {
            remove_filter('user_has_cap', [$this->twoFactor, 'stripCapabilities'], 0);
            remove_filter('map_meta_cap', [$this->twoFactor, 'stripMetaCapabilities'], 0);
            remove_filter('woocommerce_prevent_admin_access', [$this->twoFactor, 'letEnrolmentPastWooCommerce']);
            remove_action('admin_init', [$this->twoFactor, 'redirectToEnrolment']);
            remove_action('admin_page_access_denied', [$this->twoFactor, 'redirectToEnrolment']);
            remove_action('admin_notices', [$this->twoFactor, 'explainTheRestriction']);
        }

        unset($_COOKIE[LOGGED_IN_COOKIE]);

        parent::tear_down();
    }

    protected function forgetSingleSignOn(): void
    {
        (fn () => static::$authenticated = null)->bindTo(null, SingleSignOn::class)();
    }

    protected function signInWithSaml(WP_User $user): void
    {
        do_action('wp_saml_auth_existing_user_authenticated', $user, []);
    }

    protected function requireSingleSignOn(WP_User $user): void
    {
        update_user_meta($user->ID, SingleSignOn::REQUIRED_META, '1');
    }

    protected function enrolInTwoFactor(WP_User $user): void
    {
        update_user_meta($user->ID, '_two_factor_enabled_providers', ['Two_Factor_Email']);
        update_user_meta($user->ID, '_two_factor_provider', 'Two_Factor_Email');
    }

    /**
     * Puts a session in place the way wp_set_auth_cookie() does, and makes it
     * the current one.
     */
    protected function startSession(WP_User $user): string
    {
        $token = WP_Session_Tokens::get_instance($user->ID)->create(time() + HOUR_IN_SECONDS);
        $_COOKIE[LOGGED_IN_COOKIE] = wp_generate_auth_cookie($user->ID, time() + HOUR_IN_SECONDS, 'logged_in', $token);

        return $token;
    }

    public function test_a_password_login_is_refused_for_an_account_requiring_single_sign_on(): void
    {
        $this->requireSingleSignOn($this->user);

        $result = apply_filters('authenticate', $this->user, $this->user->user_login, 'password');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('gds_security_hardening_sso_required', $result->get_error_code());
    }

    /**
     * Through the real wp_authenticate(), so core's own authenticators and the
     * UserEnumeration rewrite sit on the same filter.
     */
    public function test_the_real_password_check_is_refused_too(): void
    {
        wp_set_password('correct horse battery', $this->user->ID);
        $this->requireSingleSignOn($this->user);

        $result = wp_authenticate($this->user->user_login, 'correct horse battery');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('gds_security_hardening_sso_required', $result->get_error_code());
    }

    public function test_a_wrong_password_still_reads_as_a_wrong_password(): void
    {
        $this->requireSingleSignOn($this->user);

        $result = wp_authenticate($this->user->user_login, 'wrong');

        $this->assertInstanceOf(WP_Error::class, $result);
        $this->assertSame('incorrect_password', $result->get_error_code());
    }

    public function test_a_single_sign_on_login_is_let_through(): void
    {
        $this->requireSingleSignOn($this->user);
        $this->signInWithSaml($this->user);

        $this->assertSame($this->user, apply_filters('authenticate', $this->user, '', ''));
    }

    public function test_an_account_not_requiring_it_keeps_its_password(): void
    {
        $this->assertSame($this->user, apply_filters('authenticate', $this->user, $this->user->user_login, 'password'));
    }

    public function test_another_users_single_sign_on_does_not_let_this_password_through(): void
    {
        $this->requireSingleSignOn($this->user);
        $this->signInWithSaml(self::factory()->user->create_and_get());

        $this->assertInstanceOf(WP_Error::class, apply_filters('authenticate', $this->user, '', ''));
    }

    /**
     * Inert without wp-saml-auth, so a site that loses the plugin falls back to
     * passwords rather than locking these accounts out.
     */
    public function test_it_fails_open_without_wp_saml_auth(): void
    {
        $this->requireSingleSignOn($this->user);

        $module = new class extends SingleSignOn
        {
            public static function isAvailable(): bool
            {
                return false;
            }
        };

        $this->assertSame($this->user, $module->refusePasswordLogin($this->user));
    }

    public function test_the_two_factor_challenge_is_skipped_after_single_sign_on(): void
    {
        $this->enrolInTwoFactor($this->user);
        $this->assertTrue(Two_Factor_Core::is_user_using_two_factor($this->user->ID), 'Fixture: enrolled.');

        $this->signInWithSaml($this->user);

        $this->assertFalse(Two_Factor_Core::is_user_using_two_factor($this->user->ID));
    }

    public function test_the_two_factor_challenge_stays_for_a_password_login(): void
    {
        $this->enrolInTwoFactor($this->user);
        $this->signInWithSaml(self::factory()->user->create_and_get());

        $this->assertTrue(Two_Factor_Core::is_user_using_two_factor($this->user->ID));
    }

    public function test_a_single_sign_on_session_is_marked(): void
    {
        $this->signInWithSaml($this->user);
        $token = $this->startSession($this->user);

        $session = WP_Session_Tokens::get_instance($this->user->ID)->get($token);

        $this->assertTrue($session[SingleSignOn::SESSION_KEY]);
    }

    public function test_a_password_session_is_not_marked(): void
    {
        $token = $this->startSession($this->user);

        $session = WP_Session_Tokens::get_instance($this->user->ID)->get($token);

        $this->assertArrayNotHasKey(SingleSignOn::SESSION_KEY, $session);
    }

    /**
     * On a later request, through the TwoFactor module and current_user_can():
     * an administrator who never enrolled keeps their capabilities in a single
     * sign-on session, and loses them in a password session.
     */
    public function test_a_single_sign_on_session_counts_as_enrolled_for_the_two_factor_module(): void
    {
        $this->twoFactor = new TwoFactor;
        $this->twoFactor->register();

        $this->signInWithSaml($this->user);
        $this->startSession($this->user);
        $this->forgetSingleSignOn();
        wp_set_current_user($this->user->ID);

        $this->assertTrue(current_user_can('manage_options'));
    }

    public function test_a_password_session_is_still_enforced_by_the_two_factor_module(): void
    {
        $this->twoFactor = new TwoFactor;
        $this->twoFactor->register();

        $this->startSession($this->user);
        wp_set_current_user($this->user->ID);

        $this->assertFalse(current_user_can('manage_options'));
    }

    public function test_marking_another_account_signs_it_out_everywhere(): void
    {
        $editor = self::factory()->user->create_and_get(['role' => 'administrator']);
        grant_super_admin($editor->ID);
        wp_set_current_user($editor->ID);

        $this->startSession($this->user);
        $this->assertCount(1, WP_Session_Tokens::get_instance($this->user->ID)->get_all());

        $_POST[SingleSignOn::REQUIRED_META] = '1';
        $this->module->saveSetting($this->user->ID);
        unset($_POST[SingleSignOn::REQUIRED_META]);

        $this->assertTrue(SingleSignOn::isRequiredFor($this->user->ID));
        $this->assertCount(0, WP_Session_Tokens::get_instance($this->user->ID)->get_all());
    }

    public function test_marking_your_own_account_keeps_your_session(): void
    {
        grant_super_admin($this->user->ID);
        wp_set_current_user($this->user->ID);
        $this->startSession($this->user);
        WP_Session_Tokens::get_instance($this->user->ID)->create(time() + HOUR_IN_SECONDS);

        $_POST[SingleSignOn::REQUIRED_META] = '1';
        $this->module->saveSetting($this->user->ID);
        unset($_POST[SingleSignOn::REQUIRED_META]);

        $this->assertCount(1, WP_Session_Tokens::get_instance($this->user->ID)->get_all());
    }

    public function test_someone_who_cannot_edit_users_cannot_change_it(): void
    {
        wp_set_current_user(self::factory()->user->create(['role' => 'editor']));

        $_POST[SingleSignOn::REQUIRED_META] = '1';
        $this->module->saveSetting($this->user->ID);
        unset($_POST[SingleSignOn::REQUIRED_META]);

        $this->assertFalse(SingleSignOn::isRequiredFor($this->user->ID));
    }

    public function test_unticking_it_restores_the_password(): void
    {
        grant_super_admin($this->user->ID);
        wp_set_current_user($this->user->ID);
        $this->requireSingleSignOn($this->user);

        $this->module->saveSetting($this->user->ID);

        $this->assertFalse(SingleSignOn::isRequiredFor($this->user->ID));
    }
}
