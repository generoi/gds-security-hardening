<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\AuthorArchives;
use WP_Sitemaps_Posts;
use WP_Sitemaps_Users;
use WP_UnitTestCase;

/**
 * Driven through go_to(), which runs WP::main() and so the real `request` filter,
 * rather than by calling notFound(): what matters is that the request is a 404
 * before redirect_canonical() and Yoast get to answer it differently for names
 * that exist.
 */
class AuthorArchivesTest extends WP_UnitTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->set_permalink_structure('/%postname%/');
    }

    protected function author(): string
    {
        $user = self::factory()->user->create(['role' => 'editor', 'user_nicename' => 'existing-editor']);
        self::factory()->post->create(['post_status' => 'publish', 'post_author' => $user]);

        return 'existing-editor';
    }

    public function test_an_existing_authors_archive_is_a_404(): void
    {
        $this->go_to(home_url("/author/{$this->author()}/"));

        $this->assertTrue(is_404());
        $this->assertFalse(is_author());
    }

    /**
     * The point of the module: an unknown name and an existing one must give the
     * same answer, or the archive is still a login-name oracle.
     */
    public function test_an_unknown_author_answers_the_same(): void
    {
        $this->go_to(home_url('/author/nobody-by-this-name/'));

        $this->assertTrue(is_404());
    }

    public function test_the_query_string_form_is_a_404_too(): void
    {
        $this->go_to(home_url("/?author_name={$this->author()}"));

        $this->assertTrue(is_404());
    }

    /**
     * `?author=N` on a REST collection is a filter, not an archive, and the block
     * editor's author panel uses it.
     */
    public function test_a_rest_request_keeps_its_author_query_var(): void
    {
        $vars = ['rest_route' => '/wp/v2/posts', 'author' => '1'];

        $this->assertSame($vars, (new AuthorArchives)->notFound($vars));
    }

    public function test_other_requests_are_left_alone(): void
    {
        $vars = ['pagename' => 'about'];

        $this->assertSame($vars, (new AuthorArchives)->notFound($vars));
    }

    public function test_core_drops_the_users_sitemap_and_keeps_the_rest(): void
    {
        $this->assertFalse(apply_filters('wp_sitemaps_add_provider', new WP_Sitemaps_Users, 'users'));
        $this->assertInstanceOf(
            WP_Sitemaps_Posts::class,
            apply_filters('wp_sitemaps_add_provider', new WP_Sitemaps_Posts, 'posts'),
        );
    }

    public function test_yoast_lists_no_authors(): void
    {
        $users = [self::factory()->user->create_and_get(['role' => 'editor'])];

        $this->assertSame([], apply_filters('wpseo_sitemap_exclude_author', $users));
    }
}
