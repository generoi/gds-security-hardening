<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\UserEnumeration;
use WP_REST_Request;
use WP_UnitTestCase;

/**
 * The `_embed` half of UserEnumeration.
 *
 * Driven through rest_get_server()->dispatch() rather than by calling the filter,
 * because dispatch() is exactly the path an embed sub-request takes — the one
 * that skips serve_request() and therefore rest_authentication_errors. A test
 * that called removeAuthorLink() directly would prove nothing about the route
 * this closes.
 *
 * The rest of the module — the author query vars, the authentication message,
 * the lost-password redirect — is covered in HardeningTest.
 */
class UserEnumerationTest extends WP_UnitTestCase
{
    /**
     * Attached by hand, as HardeningTest does for maybeDropAuthorQueryVars().
     *
     * The module attaches these on rest_api_init, which fires once per process
     * when rest_get_server() first builds the server. WP_UnitTestCase backs the
     * hook array up before the first test and restores it after each one, so a
     * filter added during a run is stripped again before the next — by the time
     * a later test dispatches, the registration is gone. Calling the method is
     * what keeps the assertions about the filter rather than about the harness.
     */
    protected function setUp(): void
    {
        parent::setUp();

        (new UserEnumeration)->dropAuthorLinks();
    }

    protected function post(): int
    {
        return self::factory()->post->create([
            'post_status' => 'publish',
            // Core only prints the author link for a post that has an author, so
            // without this the assertions below would hold on their own.
            'post_author' => self::factory()->user->create(['role' => 'editor']),
        ]);
    }

    protected function links(int $post): array
    {
        $request = new WP_REST_Request('GET', "/wp/v2/posts/{$post}");

        return rest_get_server()->dispatch($request)->get_links();
    }

    public function test_an_anonymous_response_carries_no_author_link_to_embed(): void
    {
        wp_set_current_user(0);

        $this->assertArrayNotHasKey('author', $this->links($this->post()));
    }

    /**
     * Over-blocking would be its own bug. Terms and featured media are published
     * content the site serves anyway, and a consumer reading a post list has no
     * other way to resolve them in one request.
     */
    public function test_the_other_embeddable_links_survive(): void
    {
        wp_set_current_user(0);

        $this->assertArrayHasKey('https://api.w.org/term', $this->links($this->post()));
    }

    /**
     * The block editor resolves post authors through this link, and anyone
     * logged in can read the users controller directly regardless.
     */
    public function test_an_authenticated_response_keeps_it(): void
    {
        wp_set_current_user(self::factory()->user->create(['role' => 'administrator']));

        $this->assertArrayHasKey('author', $this->links($this->post()));
    }

    /**
     * The filter is attached per post type at rest_api_init, so a type that
     * supports authors and opts into REST is covered without naming it. Pages are
     * the case core ships; this stands in for the custom types sites add.
     */
    public function test_it_covers_every_post_type_that_supports_authors(): void
    {
        wp_set_current_user(0);

        $page = self::factory()->post->create([
            'post_type' => 'page',
            'post_status' => 'publish',
            'post_author' => self::factory()->user->create(['role' => 'editor']),
        ]);

        $request = new WP_REST_Request('GET', "/wp/v2/pages/{$page}");

        $this->assertArrayNotHasKey(
            'author',
            rest_get_server()->dispatch($request)->get_links()
        );
    }
}
