import { expect, test } from '@playwright/test';

/**
 * The strict login policy is the one control here that can break the screen it
 * protects: nothing without this request's nonce executes, so a plugin printing a
 * raw <script> on wp-login.php stops working. This asserts the screen still
 * functions under it, in a real browser, rather than asserting the header string.
 */
test.use({ storageState: { cookies: [], origins: [] } });

test.describe('wp-login.php under a strict CSP', () => {
    test('the policy locks scripts to a nonce', async ({ request }) => {
        const csp = (await request.get('/wp-login.php')).headers()['content-security-policy'];

        expect(csp).toContain("script-src 'nonce-");
        expect(csp).toContain("'strict-dynamic'");
        expect(csp).not.toContain("'unsafe-inline'");
        expect(csp).toContain("form-action 'self'");
    });

    test('the nonce differs between requests', async ({ request }) => {
        const first = (await request.get('/wp-login.php')).headers()['content-security-policy'];
        const second = (await request.get('/wp-login.php')).headers()['content-security-policy'];

        expect(first).not.toBe(second);
    });

    test('nothing on the login screen is blocked by it', async ({ page }) => {
        const violations = [];
        page.on('console', (message) => {
            if (/content security policy/i.test(message.text())) {
                violations.push(message.text());
            }
        });

        await page.goto('/wp-login.php');
        await expect(page.locator('#loginform')).toBeVisible();

        expect(violations).toEqual([]);
    });

    test('logging in still works', async ({ page }) => {
        await page.goto('/wp-login.php');
        await page.fill('#user_login', process.env.WP_USER || 'admin');
        await page.fill('#user_pass', process.env.WP_PASSWORD || 'password');
        await page.click('#wp-submit');

        await expect(page).toHaveURL(/wp-admin/);
    });

    /**
     * Core stays clean on a failed login. The violation that does occur here is
     * limit-login-attempts-reloaded's raw <script>, which is documented and
     * covered in login-plugins.spec.js — this asserts the screen still works and
     * that core's own scripts are not what broke.
     */
    test('a failed login still renders correctly', async ({ page }) => {
        await page.goto('/wp-login.php');
        await page.fill('#user_login', 'nobody');
        await page.fill('#user_pass', 'wrong-password-here');
        await page.click('#wp-submit');

        await expect(page.locator('#login_error, .notice-error').first()).toBeVisible();
        await expect(page.locator('#loginform')).toBeVisible();
        await expect(page.locator('#user_login')).toBeVisible();
    });
});
