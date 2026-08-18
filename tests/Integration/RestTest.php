<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use WP_REST_Request;
use WP_UnitTestCase;

class RestTest extends WP_UnitTestCase
{
    protected function tearDown(): void
    {
        unset($_GET['_method'], $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']);
        $_SERVER['REQUEST_METHOD'] = 'GET';

        parent::tearDown();
    }

    protected function dispatch(string $route = '/wp/v2/types')
    {
        return rest_get_server()->dispatch(new WP_REST_Request('GET', $route));
    }

    public function test_jsonp_is_disabled(): void
    {
        $this->assertFalse(apply_filters('rest_jsonp_enabled', true));
    }

    public function test_a_get_overridden_into_a_write_is_refused(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_GET['_method'] = 'POST';

        $response = $this->dispatch();

        $this->assertSame(400, $response->get_status());
        $this->assertSame('rest_method_override_disabled', $response->get_data()['code']);
    }

    public function test_the_override_header_on_a_read_is_refused(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] = 'DELETE';

        $this->assertSame(400, $this->dispatch()->get_status());
    }

    /**
     * The block editor's own save path. @wordpress/api-fetch rewrites every PUT,
     * PATCH and DELETE into a POST carrying X-HTTP-Method-Override, so refusing
     * overrides outright breaks saving any existing post.
     */
    public function test_a_post_tunnelling_a_write_is_allowed(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] = 'PUT';

        $this->assertNotSame(400, $this->dispatch()->get_status());
    }

    public function test_an_ordinary_read_is_untouched(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';

        $this->assertSame(200, $this->dispatch()->get_status());
    }

    /**
     * rest_pre_dispatch is a filter, so a callback that ignores the value handed
     * to it discards ours. Registering last is the only thing that makes the
     * rejection survive — measured against Polylang and Gravity Forms, which
     * between them register five callbacks on this hook.
     */
    public function test_a_later_callback_that_ignores_the_result_cannot_discard_the_rejection(): void
    {
        $clobber = fn () => null;
        add_filter('rest_pre_dispatch', $clobber, 99999);

        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_GET['_method'] = 'POST';

        $status = $this->dispatch()->get_status();

        remove_filter('rest_pre_dispatch', $clobber, 99999);

        $this->assertSame(400, $status);
    }
}
