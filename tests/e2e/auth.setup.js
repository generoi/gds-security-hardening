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

    await page.goto('/wp-login.php');
    await page.fill('#user_login', process.env.WP_USER || 'admin');
    await page.fill('#user_pass', process.env.WP_PASSWORD || 'password');
    await page.click('#wp-submit');

    await expect(page).toHaveURL(/wp-admin/);
    await page.context().storageState({ path: FILE });
});
