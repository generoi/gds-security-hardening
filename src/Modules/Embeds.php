<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;
use WP_Error;
use WP_oEmbed_Controller;
use WP_REST_Request;

/**
 * Embed only from registered oEmbed providers.
 *
 * With discovery on, any URL an editor pastes is fetched server side and its
 * `<link rel="alternate" type="application/json+oembed">` followed to wherever it
 * points, and the iframe that comes back is embedded in the post. Registered
 * providers — YouTube, Vimeo, Spotify and the rest of core's list — keep working,
 * and so do embeds of this site's own posts, which core resolves locally. What
 * goes is an arbitrary site advertising its own endpoint, other WordPress sites'
 * post embeds among them.
 */
class Embeds implements Module
{
    public function register(): void
    {
        add_filter('embed_oembed_discover', '__return_false');
        add_filter('rest_request_before_callbacks', [$this, 'disableProxyDiscovery'], 10, 3);
    }

    /**
     * The editor's REST proxy calls WP_oEmbed::get_data() directly, bypassing
     * embed_oembed_discover. Override even an explicitly supplied discover=true
     * before core builds its cache key or makes any outgoing request.
     *
     * @param  array<string, mixed>  $handler
     */
    public function disableProxyDiscovery(mixed $response, array $handler, WP_REST_Request $request): mixed
    {
        $callback = $handler['callback'] ?? null;

        if (! $response instanceof WP_Error && is_array($callback)
            && ($callback[0] ?? null) instanceof WP_oEmbed_Controller
            && ($callback[1] ?? null) === 'get_proxy_item') {
            $request->set_param('discover', false);
        }

        return $response;
    }
}
