<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\Embeds;
use WP_Error;
use WP_oEmbed_Controller;
use WP_REST_Request;
use WP_UnitTestCase;

class EmbedsTest extends WP_UnitTestCase
{
    protected array $requests = [];

    public function set_up(): void
    {
        parent::set_up();
        wp_set_current_user(self::factory()->user->create(['role' => 'author']));
        add_filter('pre_http_request', [$this, 'interceptHttp'], 10, 3);
    }

    public function interceptHttp($response, $args, string $url): array
    {
        $this->requests[] = $url;
        $body = str_contains($url, '/oembed')
            ? wp_json_encode(['version' => '1.0', 'type' => 'rich', 'width' => 300, 'height' => 200,
                'html' => '<iframe src="https://www.youtube.com/embed/example"></iframe>'])
            : '<html><head><link rel="alternate" type="application/json+oembed" href="https://unregistered.example.test/oembed"></head></html>';

        return ['headers' => [], 'body' => $body, 'response' => ['code' => 200, 'message' => 'OK'], 'cookies' => []];
    }

    public function test_unregistered_providers_cannot_be_discovered_through_the_rest_proxy(): void
    {
        foreach ([null, true, false] as $discover) {
            $request = new WP_REST_Request('GET', '/oembed/1.0/proxy');
            $request->set_param('url', 'https://unregistered.example.test/page');
            if ($discover !== null) {
                $request->set_param('discover', $discover);
            }
            $response = rest_do_request($request);

            $this->assertSame(404, $response->get_status());
            $this->assertSame('oembed_invalid_url', $response->get_data()['code']);
            $this->assertSame([], $this->requests, 'Discovery must be disabled before the initial HTTP request.');
        }
    }

    public function test_a_registered_provider_still_works(): void
    {
        $request = new WP_REST_Request('GET', '/oembed/1.0/proxy');
        $request->set_param('url', 'https://www.youtube.com/watch?v=example');
        $request->set_param('discover', true);
        $response = rest_do_request($request);

        $this->assertSame(200, $response->get_status());
        $this->assertCount(1, $this->requests);
        $this->assertStringStartsWith('https://www.youtube.com/oembed?', $this->requests[0]);
    }

    public function test_this_sites_published_posts_still_embed_without_http(): void
    {
        $post = self::factory()->post->create(['post_status' => 'publish']);
        $request = new WP_REST_Request('GET', '/oembed/1.0/proxy');
        $request->set_param('url', get_permalink($post));
        $response = rest_do_request($request);

        $this->assertSame(200, $response->get_status());
        $this->assertSame([], $this->requests);
    }

    public function test_unauthenticated_callers_still_cannot_use_the_proxy(): void
    {
        wp_set_current_user(0);
        $request = new WP_REST_Request('GET', '/oembed/1.0/proxy');
        $request->set_param('url', 'https://www.youtube.com/watch?v=example');

        $this->assertSame(401, rest_do_request($request)->get_status());
        $this->assertSame([], $this->requests);
    }

    public function test_other_handlers_and_prior_errors_are_untouched(): void
    {
        $module = new Embeds;
        $request = new WP_REST_Request('GET', '/custom/route');
        $request->set_param('discover', true);
        $this->assertNull($module->disableProxyDiscovery(null, ['callback' => '__return_true'], $request));
        $this->assertTrue($request['discover']);

        $error = new WP_Error('prior_error', 'Existing rejection');
        $handler = ['callback' => [new WP_oEmbed_Controller, 'get_proxy_item']];
        $this->assertSame($error, $module->disableProxyDiscovery($error, $handler, $request));
        $this->assertTrue($request['discover']);
    }
}
