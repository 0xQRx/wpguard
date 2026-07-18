# WordPress Core — High-Value Subsystem Catalog

**This is a reference catalog, not an agent.** It exists to keep core analysis SCOPED. WordPress
core is thousands of files; a grep-map of the whole tree blows up context and finds nothing. Core
research is always **subsystem-scoped**: pick a subsystem below, point the named expert(s) at the
listed paths, and go deep there — never turn an expert loose on all of core.

Use this when the target is a `core-{version}` target (`targets/core-{version}/extracted/`). The PM
scopes work to these subsystems instead of a plugin `surface_map.md`. Lead with the **diff** of a
security release (`/diff` between the vulnerable and patched tag) to narrow to the changed subsystem
first — that is the highest-ROI entry point.

Paths are relative to the extracted core root (the directory containing `wp-includes/`, `wp-admin/`,
`wp-load.php`).

---

## 1. REST API + Batch Controller  ⭐ (trigger-bug home)

- **Where:** `wp-includes/rest-api/`, `wp-includes/rest-api/endpoints/class-wp-rest-*.php`,
  `wp-includes/rest-api/class-wp-rest-server.php`, `class-wp-rest-request.php`, and the batch
  controller (`endpoints/class-wp-rest-*controller*`, batch dispatch).
- **Why interesting:** The single richest core attack surface. `rest_do_request()` and
  `WP_REST_Request` compose requests from user data; the **batch controller** supports nesting and
  walks parallel matches/validation arrays that can desync. Method/route allow-lists enforced at the
  wrapper are frequently NOT re-applied to nested sub-requests. Schema params validated here get
  reinterpreted downstream (into `WP_Query` query vars → SQL). `rest_pre_dispatch` hooks fire before
  route auth. **This is exactly the wp2shell route-confusion SQLi surface.**
- **Point at it:** `protocol-confusion-expert` (primary), `missing-auth-expert`, `sqli-expert`,
  `idor-expert`, `critical-thinker`.

## 2. WP_Query / meta_query / WP_Meta_Query — SQL builders

- **Where:** `wp-includes/class-wp-query.php`, `class-wp-meta-query.php`, `class-wp-tax-query.php`,
  `class-wp-date-query.php`, `class-wp-user-query.php`, `wp-db.php` / `class-wpdb.php`.
- **Why interesting:** These translate query vars into raw SQL. Params that pass a REST/AJAX schema
  (e.g. `author__in`, `author__not_in`, `post__in`, `orderby`, `meta_query` keys/`compare`) are
  reinterpreted here and interpolated into WHERE/ORDER BY. Identifier and `orderby` positions cannot
  be parameterized. The **destination** of the trigger-bug's forwarded query var.
- **Point at it:** `sqli-expert` (primary), `protocol-confusion-expert`, `data-flow-expert`.

## 3. Shortcodes / do_shortcode

- **Where:** `wp-includes/shortcodes.php`, `class-wp-block-parser*`, block rendering in
  `wp-includes/blocks/`.
- **Why interesting:** `do_shortcode()` re-parses content; nested shortcodes mean outer sanitization
  is bypassed by inner re-parse. Shortcode attributes flow into output (XSS) and sometimes into
  queries (SQLi). Author/contributor content is rendered to other users.
- **Point at it:** `xss-expert`, `sqli-expert`, `protocol-confusion-expert` (nested re-dispatch).

## 4. wp_kses / sanitization & escaping layer

- **Where:** `wp-includes/kses.php`, `formatting.php` (`sanitize_*`, `esc_*`, `wp_unslash`),
  `class-wp-html-*` (HTML API).
- **Why interesting:** The allow-list HTML sanitizer and the family of `sanitize_*`/`esc_*`
  functions everything else trusts. A bypass here is systemic. Watch for context mismatches
  (sanitized for HTML, used in attribute/JS/SQL) and dangerous allowed attributes.
- **Point at it:** `xss-expert` (primary), `data-flow-expert`, `critical-thinker`.

## 5. XML-RPC

- **Where:** `xmlrpc.php`, `wp-includes/class-wp-xmlrpc-server.php`, `class-IXR-*`.
- **Why interesting:** A large, older, pre-auth-adjacent surface parsing untrusted XML. `system.multicall`
  batches calls (allow-list / auth desync territory, a cousin of the REST batch bug), `pingback.ping`
  is a classic SSRF vector, and XML parsing raises XXE.
- **Point at it:** `protocol-confusion-expert` (multicall nesting), `ssrf-expert`, `xxe-expert`,
  `missing-auth-expert`.

## 6. phar / deserialization & maybe_unserialize

- **Where:** `wp-includes/functions.php` (`maybe_unserialize`, `is_serialized`),
  `class-wp-object-cache.php`, meta/option (de)serialization, any `wp_remote_*` / file path that can
  reach a `phar://` stream wrapper.
- **Why interesting:** `maybe_unserialize()` on option/meta/user data is hidden deserialization.
  `phar://` on an attacker-influenced path triggers object injection on file ops. Type-juggling on
  serialized round-trips.
- **Point at it:** `object-injection-expert` (primary), `deserialization-expert`, `data-flow-expert`.

## 7. Auth / nonce / capability layer

- **Where:** `wp-includes/pluggable.php` (`wp_verify_nonce`, `wp_validate_auth_cookie`,
  `wp_set_auth_cookie`), `capabilities.php`, `class-wp-roles.php`, `class-wp-user.php`,
  `user.php`, `rest-api.php` permission callbacks.
- **Why interesting:** The trust root. Nonce vs. capability confusion (`wp_verify_nonce` is anti-CSRF,
  NOT authorization), `is_admin()` misuse, `__return_true` permission callbacks, capability checked on
  the wrong object/site. Auth-context inheritance of internally dispatched sub-requests.
- **Point at it:** `missing-auth-expert` (primary), `priv-esc-expert`, `protocol-confusion-expert`,
  `csrf-expert`.

## 8. Multisite / network-admin

- **Where:** `wp-includes/ms-*.php`, `class-wp-network.php`, `class-wp-site.php`, `wp-admin/network/`,
  `ms-settings.php`.
- **Why interesting:** Super-admin vs. site-admin boundary, `switch_to_blog()` context bugs (a cap
  checked on one blog, action taken on another), site/user provisioning. Distinct core auth model
  from single-site — the core scope validator treats super-admin specially.
- **Point at it:** `priv-esc-expert`, `idor-expert`, `protocol-confusion-expert` (wrong-context caps),
  `missing-auth-expert`.

## 9. Media / attachment handling

- **Where:** `wp-admin/includes/media.php`, `image.php`, `file.php`,
  `wp-includes/class-wp-image-editor*.php`, `functions.php` (`wp_handle_upload`,
  `wp_check_filetype_and_ext`), oEmbed (`class-wp-oembed*`).
- **Why interesting:** Upload → path traversal / zip-slip, image processing (EXIF, ImageMagick),
  filetype allow-list bypass, SVG. oEmbed/embed processing is an SSRF surface. Author-level upload is
  in scope.
- **Point at it:** `file-rce-expert` (primary), `ssrf-expert` (oEmbed), `xxe-expert` (SVG).

---

## How the PM uses this catalog

1. **Diff-first.** Run `/diff` between the vulnerable and patched core tag. Map changed files to the
   subsystem(s) above and scope there.
2. **One subsystem per expert batch.** Give each expert the subsystem's paths as its `priority_targets`
   — never "analyze all of core".
3. **Always include `protocol-confusion-expert`** for core work — the dispatch-desync class is core's
   signature bug and no other expert covers it.
4. **Point the listed experts** at each in-scope subsystem; run `data-flow-expert` and
   `critical-thinker` last to audit cross-subsystem dispatch-primitive invariants.
