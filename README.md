# wp-security-hardening

Security hardening for WordPress that takes no per-site configuration.

Installs as an mu-plugin. Every module is unconditional: anything needing a
per-site answer — a REST allowlist, an integration user, a CSP — belongs in that
site's own mu-plugins, not here.

```bash
composer require generoi/wp-security-hardening
```

## What it does

| Module | Control |
|---|---|
| `XmlRpc` | Exits on `XMLRPC_REQUEST` before anything registers; filters `xmlrpc_enabled` off |
| `Rest` | Disables JSONP; refuses a read overridden into a write; removes REST discovery output |
| `ApplicationPasswords` | Closes the remote authorization flow; keeps passwords to `manage_options` |
| `Headers` | HSTS, nosniff, X-Frame-Options, Referrer-Policy on frontend, admin, login **and REST** |
| `Uploads` | Keeps parser-heavy formats (PDF/EPS/SVG/HEIC/TIFF/macro-Office) to editors and above |
| `UserEnumeration` | Blocks `?author=<id>`; makes login and lost-password responses uniform |
| `Passwords` | 12-character minimum, enforced **server side** |
| `Roles` | Pins `default_role` |
| `Version` | Removes the generator tag; replaces `?ver=` with a site-salted token |
| `Filesystem` | Stops WordPress rewriting `.htaccess` |

## Three things worth knowing before you change anything

**JSONP and nosniff are one control, not two.** Core validates the `?_jsonp=`
callback against `[\w.]+` — dots included — so `?_jsonp=window.opener.approve.click`
executes as a method call in your origin. That is a Same Origin Method Execution
primitive on every reachable route, and it is the step CVE-2026-64638 used. With
JSONP off a REST response is `application/json`, and `nosniff` is what makes
`<script src="/wp-json/...">` fail rather than be sniffed into script.

**Only a read promoted to a write is refused.** `@wordpress/api-fetch` ships
`httpV1Middleware` in its *default* middleware chain, rewriting every `PATCH`,
`PUT` and `DELETE` into a `POST` with `X-HTTP-Method-Override`. Refusing overrides
outright breaks every save of an existing post. See `tests/Integration/RestTest.php`.

**The application-password gate cannot call `user_can()`.** It runs inside
`wp_validate_application_password()`, hooked on `determine_current_user`, so the
current user is still being resolved; a capability check re-enters that through
any `user_has_cap` callback and recurses until PHP runs out of memory. It reads
`$user->allcaps`, which `WP_User::get_role_caps()` builds with no filters.

## Widening a control for one site

Never fork this package. Widen from the site's own mu-plugins at a later
priority — for an integration user whose role has no `manage_options`:

```php
add_filter('wp_is_application_passwords_available_for_user', function ($available, $user) {
    return $available || $user->user_login === 'some-integration-user';
}, 20, 2);
```

Core normalises `$user` to a `WP_User` and bails on a missing one before any
filter runs, so the object is safe to rely on.

## Testing

The suite is integration-shaped on purpose. Every defect this package was written
to avoid was invisible to a unit test: the recursion above needed real
`user_has_cap` callbacks, the override rejection being discarded needed another
plugin on the same filter, and an earlier version of the upload gate broke public
Gravity Forms uploads through a path no mock would model. Polylang is installed in
the test environment because it registers four `rest_pre_dispatch` callbacks.

```bash
composer install
npx wp-env start
composer test:wp-env
```

## Deliberately out of scope

This package covers what a plugin can enforce. The rest of the
[WordPress hardening guidance](https://developer.wordpress.org/advanced-administration/security/hardening/)
lives elsewhere, and is listed here so the gap is explicit rather than forgotten:

- **`wp-config.php`** — `DISALLOW_FILE_EDIT`, `DISALLOW_FILE_MODS`,
  `DISALLOW_UNFILTERED_HTML`, `FORCE_SSL_ADMIN`, and a non-default table prefix.
  Config, not runtime.
- **File permissions** — 755/644, `wp-config.php` at 440, and keeping the web
  server user out of `plugins/`. Deployment.
- **Database privileges** — the application user should hold `SELECT`, `INSERT`,
  `UPDATE`, `DELETE` and nothing else. No `FILE` privilege, so an injection cannot
  reach the filesystem. Hosting.
- **No PHP execution under `wp-content/uploads/`** — the single highest-leverage
  control against the arbitrary-file-upload class, and not expressible in PHP.
  Web server config.
- **ImageMagick `policy.xml`** — the PDF coder reaches Ghostscript. `Uploads`
  narrows *who* can feed it; only the host policy narrows *what* it will parse.
- **Two-factor**, **WAF**, **backups**, **log monitoring**, **file integrity
  monitoring** — separate tools.
- **Automatic updates** — deliberately off under Composer-managed WordPress;
  patch latency is then a release-pipeline property, not a config one.
