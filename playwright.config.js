import { defineConfig } from '@playwright/test';

/**
 * Points at the wp-env development site, not the tests site: the PHP suite owns
 * the tests site and truncates its tables between cases.
 */
export default defineConfig({
    testDir: './tests/e2e',
    timeout: 60_000,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 1 : 0,
    workers: 1,
    reporter: process.env.CI ? 'github' : 'list',
    use: {
        baseURL: process.env.WP_BASE_URL || 'http://localhost:8888',
        trace: 'retain-on-failure',
    },
    projects: [
        { name: 'setup', testMatch: /auth\.setup\.js/ },
        {
            name: 'e2e',
            dependencies: ['setup'],
            use: { storageState: 'tests/e2e/.auth/admin.json' },
        },
    ],
});
