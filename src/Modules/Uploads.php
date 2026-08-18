<?php

namespace GeneroWP\SecurityHardening\Modules;

use GeneroWP\SecurityHardening\Module;
use WP_User;

class Uploads implements Module
{
    /**
     * Formats core leaves open to any account with upload_files, which is Author
     * and above.
     *
     * Core already covers part of this ground in get_allowed_mime_types(): it
     * unsets swf and exe for everyone, and htm|html and js for anyone without
     * unfiltered_html. Do not re-add those four here.
     *
     * psd and xcf are deliberately absent: they are application/octet-stream, so
     * core never sends them to the image editor and gating them buys no parser
     * exposure — only a restricted designer workflow.
     */
    public const RISKY_EXTENSIONS = [
        // Rasterised by ImageMagick, which delegates to Ghostscript. That is
        // native code interpreting an attacker-chosen file. ai and eps are not
        // core formats, but sites add them and image/x-eps reaches the editor
        // directly.
        'pdf', 'ai', 'eps', 'ps',
        // Markup served from our own origin. Where these are allowed at all it is
        // safe-svg that allows them and it sanitises on upload, so this is a
        // second line behind that sanitiser — SVG sanitiser bypasses are a live
        // class.
        'svg', 'svgz',
        // Decoded by ImageMagick's own coders. The same shape as the PDF case one
        // step down: Ghostscript is worse because it interprets a language rather
        // than a container, but libheif and the TIFF coder have each produced
        // memory-corruption RCEs. The sequence variants are their own mime types
        // and reach the same decoder — without them, renaming the file walks past
        // this.
        'tiff', 'tif', 'heic', 'heif', 'heics', 'heifs',
        // Executable content.
        'class',
        // Macro-enabled Office: malware distribution under our own domain.
        'docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'ppsm', 'potm',
    ];

    public function register(): void
    {
        // 9999 so this runs last. 99 is not enough: safe-svg re-adds SVG at 99
        // and WPForms Pro's rich text field re-adds its own types at 1001, either
        // of which would silently undo the gate.
        add_filter('upload_mimes', [$this, 'restrict'], 9999, 2);
    }

    /**
     * Keep the risky formats to editors and above.
     *
     * Gating rather than removing: the people who legitimately upload a PDF or an
     * EPS are editors and administrators and are unaffected. What goes away is the
     * Author-level account as a route to the parser, which is what an
     * account-takeover chain lands you, and which is a way past DISALLOW_FILE_MODS
     * — that constant blocks the plugin installer, not a document upload.
     *
     * Logged-in users only, and that is load-bearing. Gravity Forms validates a
     * submitted file with wp_check_filetype_and_ext() and no $mimes argument, so
     * core falls back to get_allowed_mime_types() and this filter runs for the
     * anonymous visitor filling in the form. Gating there would break every public
     * "attach your CV as a PDF" form and buy nothing: those files are stored
     * outside the media library, never become attachments, and so never reach
     * wp_generate_attachment_metadata() or an image editor.
     *
     * WP-CLI is exempt: it runs with no user by default, which would otherwise
     * break imports and sideloads, and a CLI session already implies shell.
     *
     * @param  array<string, string>  $mimes
     * @return array<string, string>
     */
    public function restrict(array $mimes, WP_User|int|null $user = null): array
    {
        if (defined('WP_CLI') && WP_CLI) {
            return $mimes;
        }

        if (! $user && ! is_user_logged_in()) {
            return $mimes;
        }

        $allowed = $user ? user_can($user, 'edit_pages') : current_user_can('edit_pages');

        if ($allowed) {
            return $mimes;
        }

        foreach (array_keys($mimes) as $extensions) {
            if (array_intersect(explode('|', (string) $extensions), self::RISKY_EXTENSIONS)) {
                unset($mimes[$extensions]);
            }
        }

        return $mimes;
    }
}
