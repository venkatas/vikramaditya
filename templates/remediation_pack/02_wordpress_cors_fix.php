<?php
/**
 * Plugin Name: CORS Hardening (mu-plugin)
 * Description: Replaces reflective CORS on /wp-json/* with a strict allowlist.
 * Version:     1.0.0
 *
 * Drop into wp-content/mu-plugins/. mu-plugins load on every request without
 * activation.
 *
 * What this fixes:
 *   The site was returning the request Origin header reflected back in
 *   `Access-Control-Allow-Origin` AND sending `Access-Control-Allow-Credentials: true`.
 *   Any malicious site could then read authenticated REST responses on
 *   behalf of a logged-in admin.
 *
 * What this does:
 *   1. Removes any reflective CORS headers added earlier in the request lifecycle.
 *   2. Adds CORS headers ONLY when the request Origin is in the allowlist below.
 *
 * EDIT BEFORE DEPLOYING — replace <APEX_DOMAIN> with the client's apex domain.
 */

defined('ABSPATH') || exit;

if (!function_exists('engagement_cors_allowlist')) {
    function engagement_cors_allowlist() {
        return [
            'https://<APEX_DOMAIN>',
            'https://www.<APEX_DOMAIN>',
            // Add other internal first-party origins below if needed:
            // 'https://app.<APEX_DOMAIN>',
        ];
    }
}

add_action('rest_api_init', function () {
    remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');

    add_filter('rest_pre_serve_request', function ($value) {
        header_remove('Access-Control-Allow-Origin');
        header_remove('Access-Control-Allow-Credentials');
        header_remove('Access-Control-Allow-Methods');
        header_remove('Access-Control-Allow-Headers');
        header_remove('Access-Control-Expose-Headers');

        $origin  = get_http_origin();
        $allowed = engagement_cors_allowlist();

        header('Vary: Origin', false);

        if ($origin && in_array($origin, $allowed, true)) {
            header('Access-Control-Allow-Origin: ' . esc_url_raw($origin));
            header('Access-Control-Allow-Methods: GET, OPTIONS');
            header('Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Type');
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Expose-Headers: X-WP-Total, X-WP-TotalPages, Link');
        }

        if ('OPTIONS' === ($_SERVER['REQUEST_METHOD'] ?? '')) {
            status_header(200);
            exit;
        }
        return $value;
    }, 0, 1);
}, 0);

add_action('init', function () {
    add_filter('wp_headers', function ($headers) {
        if (isset($headers['Access-Control-Allow-Origin'])) {
            $origin  = get_http_origin();
            $allowed = engagement_cors_allowlist();
            if (!$origin || !in_array($origin, $allowed, true)) {
                unset($headers['Access-Control-Allow-Origin']);
                unset($headers['Access-Control-Allow-Credentials']);
            }
        }
        return $headers;
    });
}, 0);

// Verification:
//   curl -sk -I -H "Origin: https://attacker.example" "https://<APEX_DOMAIN>/wp-json/" | grep -i access-control
//   → no Access-Control-Allow-Origin (reflection blocked)
//   curl -sk -I -H "Origin: https://<APEX_DOMAIN>" "https://<APEX_DOMAIN>/wp-json/" | grep -i access-control
//   → Access-Control-Allow-Origin: https://<APEX_DOMAIN>  (allowlist pass)
