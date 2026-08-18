import { execSync } from 'node:child_process';
import { expect, test } from '@playwright/test';

/**
 * Controls the PHP suite can only observe indirectly, asserted over real HTTP.
 */
test.describe('hardening over real HTTP', () => {
    /**
     * The entry file exits on XMLRPC_REQUEST before anything else registers, so
     * this is the only place it can be observed at all.
     */
    test('xmlrpc.php answers with nothing', async ({ request }) => {
        const response = await request.get('/xmlrpc.php');

        expect((await response.text()).trim()).toBe('');
    });

    test('an xmlrpc method call gets no response body either', async ({ request }) => {
        const response = await request.post('/xmlrpc.php', {
            headers: { 'Content-Type': 'text/xml' },
            data: '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
        });

        expect(await response.text()).not.toContain('methodResponse');
    });

    test('the login screen carries the static security headers', async ({ request }) => {
        const headers = (await request.get('/wp-login.php')).headers();

        expect(headers['x-content-type-options']).toBe('nosniff');
        expect(headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
        expect(headers['x-frame-options']).toBe('SAMEORIGIN');
    });

    test('the REST discovery link header and RSD tag are gone', async ({ request }) => {
        const response = await request.get('/');
        const body = await response.text();

        expect(response.headers()['link'] || '').not.toContain('rel="https://api.w.org/"');
        expect(body).not.toContain('rel="EditURI"');
        expect(body).not.toContain('wlwmanifest');
    });

    test('the generator tag is not emitted', async ({ request }) => {
        expect(await (await request.get('/')).text()).not.toContain('name="generator"');
    });

    /**
     * The token has to change with the core version so assets bust across an
     * upgrade, but must not be the version and must not be computable off-site.
     *
     * Only core's version is asserted on. A plugin versioning its own assets with
     * its own release number is normal and says nothing about WordPress.
     */
    test('asset URLs do not carry the WordPress version', async ({ request }) => {
        const wpVersion = execSync('npx wp-env run cli wp core version', { encoding: 'utf8' })
            .match(/\d+\.\d+(\.\d+)?/)[0];
        const body = await (await request.get('/')).text();

        for (const version of body.match(/[?&]ver=([^"'&]+)/g) || []) {
            expect(version).not.toContain(wpVersion);
        }
    });

    test('anonymous users cannot enumerate by author id', async ({ request }) => {
        const response = await request.get('/?author=1', { maxRedirects: 0 });

        expect(response.headers()['location'] || '').not.toMatch(/\/author\//);
    });
});
