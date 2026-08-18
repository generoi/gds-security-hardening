<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\Passwords;
use WP_UnitTestCase;

class HardeningTest extends WP_UnitTestCase
{
    public function test_default_role_is_pinned_whatever_the_database_says(): void
    {
        update_option('default_role', 'administrator');

        $this->assertSame('subscriber', get_option('default_role'));
    }

    public function test_xmlrpc_is_disabled(): void
    {
        $this->assertFalse(apply_filters('xmlrpc_enabled', true));
    }

    public function test_the_generator_tag_is_empty(): void
    {
        $this->assertSame('', apply_filters('the_generator', '<meta name="generator" content="WordPress 7.0" />'));
    }

    /**
     * The token has to change with the core version, but must not be the version
     * and must not be computable off-site — the previous implementation used a
     * fixed salt, so anyone could map the token back to the version it hid.
     */
    public function test_the_asset_version_token_hides_the_version(): void
    {
        global $wp_version;

        $src = apply_filters('style_loader_src', "https://example.test/style.css?ver={$wp_version}", 'handle');

        $this->assertStringNotContainsString($wp_version, $src);
        $this->assertStringContainsString('ver=', $src);
    }

    public function test_a_src_less_handle_does_not_fatal(): void
    {
        $this->assertFalse(apply_filters('style_loader_src', false, 'handle'));
    }

    public function test_a_short_password_is_refused_server_side(): void
    {
        $this->assertWPError((new Passwords)->validate('short'));
    }

    public function test_a_long_enough_password_is_accepted(): void
    {
        $this->assertTrue((new Passwords)->validate(str_repeat('a', Passwords::MINIMUM_LENGTH)));
    }

    /**
     * Arming only on `author=<id>` is deliberate: WP::parse_request() copies
     * rewrite matches into query_vars after the query_vars filter, so dropping
     * author_name unconditionally breaks /author/nicename/ archives too.
     */
    public function test_author_archives_still_work_without_an_author_id_in_the_query(): void
    {
        $_SERVER['QUERY_STRING'] = '';
        do_action('init');

        $this->assertContains('author_name', apply_filters('query_vars', ['author', 'author_name']));
    }
}
