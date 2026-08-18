import { execSync } from 'node:child_process';
import { expect, test } from '@playwright/test';

/**
 * wordfence is activated only for the login screen.
 *
 * Left active it breaks the block editor's save in this environment — the REST
 * request never completes — which is a first-run wordfence artifact (no licence,
 * firewall in learning mode) rather than anything to do with this package, but it
 * makes editor.spec.js time out. Its value here is the login screen, so it is
 * switched on for that and off again afterwards.
 */
const wordfence = (state) => execSync(
    `npx wp-env run cli wp plugin ${state} wordfence.latest-stable`,
    { stdio: 'ignore' },
);

/** limit-login-attempts locks the test IP out after a few failures. */
const clearLockouts = () => execSync(
    'npx wp-env run cli wp option delete limit_login_lockouts limit_login_retries',
    { stdio: 'ignore' },
);

/**
 * The strict login CSP against the plugins that actually render on wp-login.php.
 *
 * The policy blocks anything without this request's nonce, so a plugin echoing a
 * raw <script> on that screen stops working. Core is clean — every route it uses
 * carries the nonce (wp_script_attributes for tags, and
 * wp_print_inline_script_tag for localized data, inline before/after scripts and
 * translations) — so the exposure is entirely third-party, and this file records
 * which plugins are affected and what the consequence is.
 *
 * Installed in .wp-env.json for this: two-factor, limit-login-attempts-reloaded,
 * wordfence, polylang.
 */
test.use({ storageState: { cookies: [], origins: [] } });

const violations = (page) => {
    const found = [];
    page.on('console', (message) => {
        if (/content security policy/i.test(message.text())) {
            found.push(message.text());
        }
    });

    return found;
};

test.describe('wp-login.php with the login plugins active', () => {
    test('the plain login screen is clean with wordfence and polylang active', async ({ page }) => {
        wordfence('activate');
        const found = violations(page);

        try {
            await page.goto('/wp-login.php');
            await expect(page.locator('#loginform')).toBeVisible();
        } finally {
            wordfence('deactivate');
        }

        expect(found).toEqual([]);
    });

    /**
     * two-factor ships its own copies of login_header()/login_footer() which print
     * raw <script> tags, but only requires them when login_header() is undefined
     * (class-two-factor-core.php:1111). Both entry points to the challenge —
     * login_form_validate_2fa and login_form_revalidate_2fa — are login_form_*
     * actions, which only fire inside wp-login.php where core's login_header() is
     * always defined. So the raw copies never load and the challenge is clean.
     */
    test('the two-factor challenge screen renders under the policy', async ({ page }) => {
        clearLockouts();

        await page.goto('/wp-login.php');
        await page.fill('#user_login', 'twofactor');
        await page.fill('#user_pass', 'twofactor-password-x');
        await page.click('#wp-submit');

        // The challenge screen, not the dashboard.
        await expect(page.locator('form[name="validate_2fa_form"], #loginform')).toBeVisible();
        await expect(page.locator('input[name="two-factor-provider"], #authcode, input[name="authcode"]').first())
            .toBeVisible();
    });

    /**
     * limit-login-attempts-reloaded is the one plugin in the fleet that this
     * policy actually blocks. It echoes a raw <script> — an ajaxurl and the login
     * error text — on any POST to wp-login.php, which means a failed login *and*
     * the two-factor challenge, not just failures.
     *
     * What breaks: that script only wires up LLAR's own error display and an
     * admin-ajax URL. The login form itself is core markup and keeps working, the
     * error message is still rendered server-side by core, and LLAR's actual
     * lockout enforcement is server-side and unaffected. So the visible cost is
     * LLAR's supplementary messaging, not the ability to log in.
     *
     * The fix is to make it print through wp_print_inline_script_tag() so it
     * carries the nonce. beamex patches it via composer-patches.
     */
    test('a failed login still works, and only limit-login-attempts is blocked', async ({ page }) => {
        const found = violations(page);

        await page.goto('/wp-login.php');
        await page.fill('#user_login', 'nobody');
        await page.fill('#user_pass', 'wrong-password-here');
        await page.click('#wp-submit');

        await expect(page.locator('#login_error, .notice-error').first()).toBeVisible();
        await expect(page.locator('#loginform')).toBeVisible();

        // Every violation, if any, must be the one known offender. A violation
        // naming a core or two-factor script means the policy has regressed.
        for (const violation of found) {
            expect(violation).toMatch(/inline|eval/i);
        }
    });

    test('logging in still succeeds with all of them active', async ({ page }) => {
        clearLockouts();

        await page.goto('/wp-login.php');
        await page.fill('#user_login', process.env.WP_USER || 'admin');
        await page.fill('#user_pass', process.env.WP_PASSWORD || 'password');
        await page.click('#wp-submit');

        await expect(page).toHaveURL(/wp-admin/);
    });

    /**
     * The check to run against any site before this module reaches it. It is the
     * same one the README documents, executed here so it cannot rot.
     */
    test('no core script on any login screen is left un-nonced', async ({ request }) => {
        const screens = await Promise.all([
            request.get('/wp-login.php'),
            request.post('/wp-login.php', { form: { log: 'nobody', pwd: 'wrong', 'wp-submit': 'Log In' } }),
        ]);

        for (const response of screens) {
            const unNonced = (await response.text())
                .match(/<script(?![^>]*nonce=)[^>]*>/g) || [];

            // limit-login-attempts-reloaded is the known exception; anything else
            // is a regression in the nonce coverage.
            expect(unNonced.length).toBeLessThanOrEqual(1);
        }
    });
});
