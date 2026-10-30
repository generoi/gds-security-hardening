<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\AuthorArchives;
use WP_Posts_List_Table;
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

    /**
     * Core's list tables run wp() inside the admin, so the filter fires there
     * too, with the author as a list filter rather than an archive.
     */
    public function test_admin_requests_keep_their_author_query_var(): void
    {
        set_current_screen('edit.php');

        $vars = ['post_type' => 'post', 'author' => '3', 'orderby' => 'date'];

        try {
            $this->assertSame($vars, (new AuthorArchives)->notFound($vars));
        } finally {
            set_current_screen('front');
        }
    }

    /**
     * The screen that broke: WP_Posts_List_Table forces `author=<id>` for a user
     * without edit_others_posts, and wp_edit_posts_query() then runs the real
     * `request` filter. An Author has to see their own posts.
     */
    public function test_an_author_sees_their_own_posts_in_the_admin_list(): void
    {
        require_once ABSPATH.'wp-admin/includes/post.php';
        require_once ABSPATH.'wp-admin/includes/class-wp-list-table.php';
        require_once ABSPATH.'wp-admin/includes/class-wp-posts-list-table.php';

        $author = self::factory()->user->create(['role' => 'author']);
        $post = self::factory()->post->create(['post_status' => 'publish', 'post_author' => $author]);
        self::factory()->post->create(['post_status' => 'publish']);

        wp_set_current_user($author);
        set_current_screen('edit.php');

        try {
            $table = new WP_Posts_List_Table(['screen' => 'edit-post']);
            $table->prepare_items();

            $this->assertSame($author, (int) $_GET['author'], 'core forces the author filter for this role');
            $this->assertFalse(is_404());
            $this->assertSame([$post], wp_list_pluck($GLOBALS['wp_query']->posts, 'ID'));
        } finally {
            unset($_GET['author']);
            set_current_screen('front');
        }
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
