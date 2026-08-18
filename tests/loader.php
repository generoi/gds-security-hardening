<?php

/*
Plugin Name:  Security Hardening loader
Description:  Loads the package in a plain WordPress install, the way Bedrock's autoloader does in production
Version:      1.0.0
*/

/*
 * WordPress only loads mu-plugins that sit directly in WPMU_PLUGIN_DIR — a
 * package installed into a subdirectory needs something to require it. Bedrock's
 * autoloader does that in production by globbing mu-plugins/-*-/-*-.php; plain
 * installs, including wp-env, need this stub.
 */
require_once WPMU_PLUGIN_DIR.'/wp-security-hardening/wp-security-hardening.php';
