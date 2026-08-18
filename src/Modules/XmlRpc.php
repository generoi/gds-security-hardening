<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;

/**
 * Disable XML-RPC.
 *
 * The entry file exits on XMLRPC_REQUEST before this ever loads, which covers
 * xmlrpc.php itself. This covers everything that asks whether XML-RPC is
 * available, core's RSD link output included.
 */
class XmlRpc implements Module
{
    public function register(): void
    {
        add_filter('xmlrpc_enabled', '__return_false');
    }
}
