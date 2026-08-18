<?php

namespace GeneroWP\SecurityHardening\Tests\Integration;

use GeneroWP\SecurityHardening\Modules\Uploads;
use WP_UnitTestCase;

class UploadsTest extends WP_UnitTestCase
{
    protected function allowedFor(?int $userId): array
    {
        wp_set_current_user($userId ?? 0);

        return get_allowed_mime_types();
    }

    public function test_an_editor_keeps_the_risky_formats(): void
    {
        $mimes = $this->allowedFor(self::factory()->user->create(['role' => 'editor']));

        $this->assertArrayHasKey('pdf', $mimes);
    }

    public function test_an_author_loses_them(): void
    {
        $mimes = $this->allowedFor(self::factory()->user->create(['role' => 'author']));

        $this->assertArrayNotHasKey('pdf', $mimes);
    }

    /**
     * Public form uploads run as nobody. Gravity Forms validates a submission
     * with wp_check_filetype_and_ext() and no $mimes argument, so this filter runs
     * for the anonymous visitor — gating there breaks every "attach your CV as a
     * PDF" form, and buys nothing, because those files never become attachments.
     */
    public function test_an_anonymous_visitor_is_untouched(): void
    {
        $this->assertArrayHasKey('pdf', $this->allowedFor(null));
    }

    /**
     * heics and heifs are their own mime types and reach the same libheif
     * decoder. Without them, renaming the file walks past the gate.
     */
    public function test_the_heic_sequence_variants_are_gated_too(): void
    {
        $mimes = $this->allowedFor(self::factory()->user->create(['role' => 'author']));

        $this->assertArrayNotHasKey('heic', $mimes);
        $this->assertArrayNotHasKey('heics', $mimes);
        $this->assertArrayNotHasKey('heifs', $mimes);
    }

    /**
     * Core already unsets these itself; repeating them here would imply it does
     * not.
     */
    public function test_it_does_not_duplicate_what_core_already_removes(): void
    {
        $module = new Uploads;

        $this->assertNotContains('swf', $module::RISKY_EXTENSIONS);
        $this->assertNotContains('exe', $module::RISKY_EXTENSIONS);
        $this->assertNotContains('html', $module::RISKY_EXTENSIONS);
        $this->assertNotContains('js', $module::RISKY_EXTENSIONS);
    }

    /**
     * safe-svg re-adds SVG at priority 99 and WPForms Pro at 1001. Running at 99
     * silently loses to both.
     */
    public function test_it_runs_after_a_plugin_that_re_adds_a_type(): void
    {
        $reAdd = function (array $mimes): array {
            $mimes['svg'] = 'image/svg+xml';

            return $mimes;
        };
        add_filter('upload_mimes', $reAdd, 1001);

        $mimes = $this->allowedFor(self::factory()->user->create(['role' => 'author']));

        remove_filter('upload_mimes', $reAdd, 1001);

        $this->assertArrayNotHasKey('svg', $mimes);
    }
}
