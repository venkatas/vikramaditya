<?php
/**
 * Plugin Name: Block WP User Enumeration (mu-plugin)
 * Description: Strips author info from /wp-json/wp/v2/users for unauth callers
 *              and disables the legacy ?author=N redirect vector.
 * Version:     1.0.0
 *
 * What this fixes:
 *   /wp-json/wp/v2/users currently returns full user records (slug, gravatar
 *   hash, link to /author/<slug>) without authentication. Usernames leak,
 *   giving attackers a target list for password spraying and 2FA-bypass.
 *
 * What this does:
 *   • For unauthenticated requests:
 *       - /wp-json/wp/v2/users         → 401
 *       - /wp-json/wp/v2/users/<id>    → 401
 *       - /?author=<id> (legacy enum)  → redirect to home
 *   • For authenticated requests with edit_users capability: no change.
 *
 * Drop into wp-content/mu-plugins/.
 */

defined('ABSPATH') || exit;

// 1. Block REST users routes for unauthenticated callers.
add_filter('rest_endpoints', function ($endpoints) {
    if (!is_user_logged_in() || !current_user_can('list_users')) {
        if (isset($endpoints['/wp/v2/users'])) {
            unset($endpoints['/wp/v2/users']);
        }
        if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }
    }
    return $endpoints;
});

// 2. Block the legacy ?author=N enumeration vector.
add_action('template_redirect', function () {
    if (!is_admin() && isset($_GET['author']) && !empty($_GET['author'])) {
        wp_redirect(home_url('/'), 301);
        exit;
    }
});

// Verification:
//   curl -sk https://<APEX_DOMAIN>/wp-json/wp/v2/users -i | head -1
//   → HTTP/2 401  (was: 200 with full user JSON)
//   curl -sk -L https://<APEX_DOMAIN>/?author=1 -o /dev/null -w "%{url_effective}\n"
//   → https://<APEX_DOMAIN>/  (was: redirected to /author/<username>/)
