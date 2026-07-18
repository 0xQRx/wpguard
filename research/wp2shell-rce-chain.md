# wp2shell: read-only SQLi → unauthenticated RCE (full chain + lessons)

CVE-2026-63030 (REST `/batch/v1` route confusion) + CVE-2026-60137 (`WP_Query::author__not_in`
SQLi). Affected WordPress core 6.9.0–6.9.4 / 7.0.0–7.0.1 (SQLi sink alone: 6.8.0–6.8.5). Fixed
6.8.6 / 6.9.5 / 7.0.2. Route confusion + SQLi by Adam Kues (Assetnote / Searchlight Cyber); the
stock-default RCE chain (oEmbed → changeset → re-entry) by Mustafa Can İPEKÇİ (nukedx).

This document records the **escalation** from a read-only SQLi to unauthenticated admin creation, the
exact quirks that make it fire, and the methodology lessons. Reproduced and write-oracle-verified
end-to-end against a pinned 6.9.4 sandbox (user count 5→6, `uid=33(www-data)`).

## The delivery bug (summary)

`serve_batch_request_v1()` builds parallel `$matches` (handler) and `$validation` arrays. A
sub-request whose path fails `wp_parse_url()` is appended to `$validation` but NOT `$matches`, so the
arrays desync and a sub-request is dispatched under a *different* sub-request's handler while carrying
a "validated" flag from the route it is not running under. Nesting this twice: (1) a `POST
/wp/v2/posts` carrying a `requests` body runs under the batch handler (method allow-list bypassed);
(2) inside it, a `GET /wp/v2/users?author_exclude=…` runs under posts `get_items()`, where
`author_exclude` → `WP_Query::author__not_in`. `author__not_in` skips its `absint` sanitization when
it arrives as a scalar string (the `is_array()` branch is not taken), so it is interpolated raw into
`... post_author NOT IN (<value>)` — a pre-auth blind SQLi.

## The escalation: read-only SQLi → RCE

mysqli runs no stacked statements, so the injection is `SELECT`-only. It becomes RCE by **forging
objects**, not writing SQL:

1. **Row forgery / object-cache poisoning.** `UNION SELECT wp_posts.*` fabricates `wp_posts` rows.
   `WP_Query` hydrates them into `WP_Post` objects and caches them by ID — with no check they came
   from a real table write. Preconditions: force full columns by defeating `split_the_query`
   (`posts_per_page >= 500` or `-1`), and keep the tail UNION-safe (`orderby=rand` → `ORDER BY
   RAND()`, or comment with `-- `). Both `per_page` and `orderby` are smuggled by validating the
   sub-request against `/wp/v2/widgets` (whose schema lacks them) while executing under posts.

2. **Render-time write (read-only SQLi → real DB write).** A forged post with **`ID=0`** and **empty
   `post_password`** carrying `[embed width="500" height="750"]<self-url>[/embed]` content is rendered
   by `get_items` (`context=view`). Because the global `$post->ID` is falsy, `WP_Embed::shortcode()`
   takes the `oembed_cache` → `wp_insert_post()` branch, creating a **real** post with predictable
   slug `md5($url . serialize($attr))` and a real auto-increment ID (recoverable via blind SQLi).
   - **Both conditions are required** (verified by controlled matrix + `general_log`):
     `ID=0` selects the `oembed_cache` branch (a real ID takes the postmeta branch → no usable post);
     empty `post_password` is required or `post_password_required()` blanks `content.rendered` and
     `the_content` never runs → zero writes.
   - Other unauth render→write primitives: `core/rss` → `_site_transient_feed_<md5(url)>` (attacker
     controls key+value); `core/navigation` → `wp_navigation` post (fixed slug, single-shot);
     `core/calendar` → `wp_calendar_block_has_published_posts` option.

3. **User-switch elevation.** A forged `customize_changeset` (status `future`, JSON body carrying
   `user_id` = the real admin) anchored on the real oembed_cache IDs drives
   `_wp_customize_publish_changeset` → `WP_Customize_Manager::_publish_changeset_values` →
   `wp_set_current_user( admin )`. This switch is process-global and sticky for the rest of the
   request.

4. **Dynamic-hook re-entry.** A forged post with status/type chosen to collide with
   `do_action("{$new_status}_{$post->post_type}")` (in `wp_transition_post_status`) fires
   `parse_request` (bound to `rest_api_loaded`) → nested REST dispatch, now in admin context. The
   forged graph is wired through `post_parent` loops so the transition fires during the read.

5. **Impact.** A `POST /wp/v2/users` riding in the same batch passes
   `current_user_can('create_users')` → new administrator with an attacker-chosen password. Then:
   log in, upload a plugin webshell, execute. No FILE privilege, no persistent object cache, no
   plugins, no misconfig.

## Why it works (root cause — the four broken assumptions)

- **The object cache trusts the query, not the database.** A UNION row is indistinguishable from a
  real post for the rest of the request.
- **Content rendering performs privileged writes with no capability check.** oEmbed/RSS/nav/calendar
  call `wp_insert_post`/`update_option` while rendering "trusted" content; forged content makes that
  an unauth write primitive.
- **`wp_set_current_user()` is process-global and sticky.** Publishing a changeset switches to the
  changeset's stored `user_id` (attacker-controlled) and never reverts within the request.
- **The batch endpoint is the glue.** One request forges, renders, transitions, and re-enters the
  REST stack sharing one object cache and one global user state — so the elevation carries from the
  forge to the `create_users` call with no persistence needed.

## Methodology lessons (transferable to any audit)

- **A read-only SQLi is not automatically "read only" in impact.** In WordPress a `SELECT`-only
  injection into a `WP_Query` collection is a row-forgery / object-cache-poisoning primitive. Ask what
  consumes a post object later in the same request.
- **Never kill a candidate on static analysis alone.** This chain was wrongly declared "blocked"
  twice from code reading. Reach for a runtime oracle before concluding.
- **"The response looked right" is not verification.** A silently-broken forge returned valid-looking
  posts while writing nothing to the DB (an invalid empty `0x` SQL literal; a space in `post_password`
  suppressing render). Confirm writes/forges/priv-changes against `mysql.general_log` (`SET GLOBAL
  general_log='ON'`) and by diffing the real signal (user count, target row) before vs after.

## References

- Searchlight Cyber / Assetnote (route confusion + SQLi): https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/
- nukedx RCE chain (oEmbed → changeset → re-entry): https://gist.github.com/mcipekci/2b5027f965153d8058bbcfd63006ef79
- WordPress 7.0.2 release: https://wordpress.org/news/2026/07/wordpress-7-0-2-release/
- Advisories: GHSA-ff9f-jf42-662q, GHSA-fpp7-x2x2-2mjf
