import { expect, test } from '@playwright/test';

/**
 * The ?rest_route= form rather than /wp-json/: it reaches the same dispatcher and
 * does not depend on pretty permalinks being configured, which the test
 * environment does not guarantee.
 */
test.describe('REST hardening over real HTTP', () => {
    test('JSONP is refused', async ({ request }) => {
        const response = await request.get('/?rest_route=/wp/v2/types&_jsonp=alert');
        const body = await response.text();

        expect(body).not.toContain('/**/alert(');
        expect(body).toContain('rest_callback_disabled');
    });

    test('a read overridden into a write is refused', async ({ request }) => {
        const response = await request.get('/?rest_route=/wp/v2/types&_method=POST');

        expect(response.status()).toBe(400);
        expect(await response.text()).toContain('rest_method_override_disabled');
    });

    test('REST responses carry nosniff', async ({ request }) => {
        const response = await request.get('/?rest_route=/wp/v2/types');

        expect(response.headers()['x-content-type-options']).toBe('nosniff');
    });

    test('the frontend carries the static headers', async ({ request }) => {
        const headers = (await request.get('/')).headers();

        expect(headers['x-content-type-options']).toBe('nosniff');
        expect(headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    });

    test('the REST discovery link header is gone', async ({ request }) => {
        const link = (await request.get('/')).headers()['link'] || '';

        expect(link).not.toContain('rel="https://api.w.org/"');
    });

    test('the remote application authorization screen is closed', async ({ page }) => {
        const response = await page.goto('/wp-admin/authorize-application.php?app_name=test');

        expect(response.status()).toBe(403);
    });
});
