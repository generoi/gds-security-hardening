<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;

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
    }
}
