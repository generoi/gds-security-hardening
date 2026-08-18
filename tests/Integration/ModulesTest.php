<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Module;
use GeneroWP\SecurityHardening\Modules\Filesystem;
use GeneroWP\SecurityHardening\Modules\Uploads;
use GeneroWP\SecurityHardening\Plugin;
use WP_UnitTestCase;

class ModulesTest extends WP_UnitTestCase
{
    /**
     * Deliberately does not re-register every module to prove the point. Doing
     * that leaves the whole suite with doubled callbacks and the next test to
     * touch capabilities dies in has_cap — which is how this test was written the
     * first time.
     */
    public function test_the_filter_can_remove_a_module_from_the_list(): void
    {
        $callback = fn (array $modules) => array_values(array_diff($modules, [Filesystem::class]));
        add_filter(Plugin::FILTER_MODULES, $callback);

        $modules = apply_filters(Plugin::FILTER_MODULES, Plugin::MODULES);

        remove_filter(Plugin::FILTER_MODULES, $callback);

        $this->assertNotContains(Filesystem::class, $modules);
        $this->assertContains(Uploads::class, $modules);
    }

    public function test_registering_a_module_is_what_adds_its_hooks(): void
    {
        remove_filter('flush_rewrite_rules_hard', '__return_false', 99);
        $this->assertTrue((bool) apply_filters('flush_rewrite_rules_hard', true));

        (new Filesystem)->register();

        $this->assertFalse((bool) apply_filters('flush_rewrite_rules_hard', true));
    }

    public function test_every_registered_module_implements_the_interface(): void
    {
        foreach (Plugin::MODULES as $module) {
            $this->assertTrue(is_subclass_of($module, Module::class), "{$module} is not a Module.");
        }
    }

    public function test_booting_twice_does_not_register_anything_twice(): void
    {
        $before = count($GLOBALS['wp_filter']['upload_mimes']->callbacks[9999] ?? []);

        Plugin::boot();

        $this->assertSame($before, count($GLOBALS['wp_filter']['upload_mimes']->callbacks[9999] ?? []));
    }

    /**
     * avif is a core mime type and decodes through the same libheif family as
     * heic, and is deliberately not gated: it is a routine image format an author
     * has reason to upload. The gate covers formats an author has no routine need
     * for, not every format that reaches a risky parser.
     */
    public function test_the_gate_does_not_extend_to_routine_image_formats(): void
    {
        $this->assertNotContains('avif', Uploads::RISKY_EXTENSIONS);
        $this->assertNotContains('webp', Uploads::RISKY_EXTENSIONS);
        $this->assertNotContains('jpg', Uploads::RISKY_EXTENSIONS);
    }

    /**
     * Every gated extension has to be one core actually serves, or a site adds —
     * otherwise the entry is decoration.
     */
    public function test_every_gated_extension_is_real(): void
    {
        $core = [];
        foreach (array_keys(wp_get_mime_types()) as $key) {
            $core = [...$core, ...explode('|', $key)];
        }

        // Not core formats; sites add them, and the gate covers them for when
        // they do.
        $added = ['ai', 'eps', 'ps', 'svg', 'svgz'];

        foreach (array_diff(Uploads::RISKY_EXTENSIONS, $added) as $extension) {
            $this->assertContains($extension, $core, "{$extension} is gated but core never serves it.");
        }
    }
}
