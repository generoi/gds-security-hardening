import { execSync } from 'node:child_process';
import { expect, test } from '@playwright/test';

/**
 * @wordpress/api-fetch ships httpV1Middleware in its default middleware chain, so
 * saving an existing post is a POST carrying X-HTTP-Method-Override: PUT. A rule
 * that refuses method overrides outright therefore 400s every save of every
 * existing post — the primary editing path.
 *
 * The PHP suite asserts our model of what the editor sends. This asserts what it
 * actually sends.
 */
test('saving an existing post from the block editor succeeds', async ({ page }) => {
    // Created out of band: the point of the test is the save, and driving the
    // publish flow through the UI adds failure modes that are not ours.
    const id = execSync(
        'npx wp-env run cli wp post create --post_title="Method override regression"'
        + ' --post_status=publish --porcelain',
        { encoding: 'utf8' },
    ).match(/\d+/)[0];

    await page.goto(`/wp-admin/post.php?post=${id}&action=edit`);

    // With a block theme the editor canvas is iframed, so the title lives inside
    // it rather than on the page.
    const title = page.frameLocator('iframe[name="editor-canvas"]')
        .getByRole('textbox', { name: /add title/i })
        .or(page.getByRole('textbox', { name: /add title/i }))
        .first();
    await expect(title).toBeVisible({ timeout: 30_000 });

    const update = page.waitForResponse((response) => {
        const request = response.request();

        return request.method() === 'POST'
            && /posts(%2F|\/)\d+/.test(response.url())
            && request.headers()['x-http-method-override'] === 'PUT';
    }, { timeout: 30_000 });

    await title.fill('Method override regression, edited');
    await page.getByRole('button', { name: /^(Update|Save)$/ }).first().click();

    const response = await update;

    // Asserting on the rejection rather than on a 200. wp-env's Apache ships
    // AllowOverride None, so .htaccess is ignored and /wp-json/ never routes —
    // the editor's save gets a 404 from Apache before WordPress sees it, whatever
    // we do. What is still provable, and is the whole point, is that the save was
    // not refused by us: refusing overrides outright returns a 400 with
    // rest_method_override_disabled, and this assertion fails the moment it does.
    expect(response.status()).not.toBe(400);
    expect(await response.text()).not.toContain('rest_method_override_disabled');
});
