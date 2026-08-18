import { execSync } from 'node:child_process';
import { expect, test as setup } from '@playwright/test';

const FILE = 'tests/e2e/.auth/admin.json';

setup('authenticate as administrator', async ({ page }) => {
    // The welcome guide is a modal over the editor canvas, so every editor test
    // would otherwise start by dismissing it.
    execSync(
        `npx wp-env run cli wp user meta update 1 wp_persisted_preferences `
        + `'{"core/edit-post":{"welcomeGuide":false},"core":{"welcomeGuide":false}}' --format=json`,
        { stdio: 'ignore' },
    );

    // wordfence is activated by the login specs and deactivated again, but an
    // interrupted run can leave it on, and while it is on the block editor's save
    // never completes. Normalise it here so the suite starts from a known state.
    execSync('npx wp-env run cli wp plugin deactivate wordfence.latest-stable', { stdio: 'ignore' });

    // The failed-login specs trip limit-login-attempts' lockout, which then
    // blocks every later login and makes the suite order-dependent. Clear it.
    execSync(
        'npx wp-env run cli wp option delete limit_login_lockouts limit_login_retries',
        { stdio: 'ignore' },
    );

    // A separate account enrolled in two-factor, so the challenge screen can be
    // exercised without putting the admin used for every other spec behind it.
    execSync(
        `npx wp-env run cli wp eval '`
        + `$id = username_exists("twofactor") ?: wp_create_user("twofactor", "twofactor-password-x", "twofactor@example.test");`
        + `(new WP_User($id))->set_role("administrator");`
        + `update_user_meta($id, "_two_factor_enabled_providers", ["Two_Factor_Email"]);`
        + `update_user_meta($id, "_two_factor_provider", "Two_Factor_Email");'`,
        { stdio: 'ignore' },
    );

    await page.goto('/wp-login.php');
    await page.fill('#user_login', process.env.WP_USER || 'admin');
    await page.fill('#user_pass', process.env.WP_PASSWORD || 'password');
    await page.click('#wp-submit');

    await expect(page).toHaveURL(/wp-admin/);
    await page.context().storageState({ path: FILE });
});
