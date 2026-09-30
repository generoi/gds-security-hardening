import { execSync } from 'node:child_process';
import { expect, test } from '@playwright/test';

/**
 * Enrolment through a real browser, with WooCommerce active.
 *
 * The capability tests in TwoFactorTest.php passed while the flow was broken on
 * a WooCommerce site: WC_Admin::prevent_admin_access() sends anyone without
 * edit_posts, manage_woocommerce or view_admin_dashboard to My Account, and an
 * unenrolled user has none of them. They were redirected to profile.php, then
 * on to /my-account/#two-factor-options, and could never enrol. And a screen
 * they may not open, like edit.php, died with "Sorry, you are not allowed to
 * access this page" before the redirect to their profile ran, because core
 * checks page access in menu.php ahead of admin_init. Only requests through
 * wp-admin show either, so they are asserted here.
 *
 * The module is enabled for these accounts only, and only while this file runs,
 * by tests/two-factor-e2e.php.
 */
test.use({ storageState: { cookies: [], origins: [] } });

const wp = (php) => execSync(`npx wp-env run cli wp eval '${php}'`, { stdio: 'ignore' });

test.beforeAll(() => {
    execSync('npx wp-env run cli wp option delete limit_login_lockouts limit_login_retries', { stdio: 'ignore' });
    execSync('npx wp-env run cli wp option update gds_e2e_require_two_factor 1', { stdio: 'ignore' });

    // An administrator the module enforces on, deliberately not enrolled.
    wp('$id = username_exists("unenrolled") ?: wp_create_user("unenrolled", "unenrolled-password-x", "unenrolled@example.test");'
        + '(new WP_User($id))->set_role("administrator");'
        + 'update_user_meta($id, GDS_E2E_REQUIRE_TWO_FACTOR, "1");'
        + 'delete_user_meta($id, "_two_factor_enabled_providers");'
        + 'delete_user_meta($id, "_two_factor_provider");');

    // A WooCommerce customer the site exempts: WooCommerce must keep them out.
    wp('$id = username_exists("shopper") ?: wp_create_user("shopper", "shopper-password-x", "shopper@example.test");'
        + '(new WP_User($id))->set_role("customer");');
});

test.afterAll(() => {
    execSync('npx wp-env run cli wp option delete gds_e2e_require_two_factor', { stdio: 'ignore' });
});

const logIn = async (page, user, password) => {
    await page.goto('/wp-login.php');
    await page.fill('#user_login', user);
    await page.fill('#user_pass', password);
    await page.click('#wp-submit');
    await page.waitForLoadState('domcontentloaded');
};

test('an unenrolled administrator is sent to their profile, where they can enrol', async ({ page }) => {
    await logIn(page, 'unenrolled', 'unenrolled-password-x');

    await page.goto('/wp-admin/');

    await expect(page).toHaveURL(/\/wp-admin\/profile\.php/);
    await expect(page.locator('#two-factor-options')).toBeVisible();
    await expect(page.locator('.notice-error')).toContainText('Two-factor authentication is required');
});

test('their profile stays reachable when opened directly', async ({ page }) => {
    await logIn(page, 'unenrolled', 'unenrolled-password-x');

    await page.goto('/wp-admin/profile.php');

    await expect(page).toHaveURL(/\/wp-admin\/profile\.php/);
    await expect(page.locator('#two-factor-options')).toBeVisible();
});

test('everything else in wp-admin still sends them back to their profile', async ({ page }) => {
    await logIn(page, 'unenrolled', 'unenrolled-password-x');

    await page.goto('/wp-admin/edit.php');

    await expect(page).toHaveURL(/\/wp-admin\/profile\.php/);
});

test('a customer the site exempts is still kept out of wp-admin by WooCommerce', async ({ page }) => {
    await logIn(page, 'shopper', 'shopper-password-x');

    await page.goto('/wp-admin/');

    await expect(page).not.toHaveURL(/\/wp-admin\//);
});
