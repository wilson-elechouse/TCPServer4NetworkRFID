<?php
/**
 * Plugin Name: ELECHOUSE RFID Broker Auth Check
 * Description: Local-only REST endpoint used by the RFID TCP Broker to verify WordPress login cookies.
 * Version:     0.1.0
 * Author:      ELECHOUSE
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_action( 'rest_api_init', function () {
	register_rest_route(
		'elechouse-rfid/v1',
		'/auth-check',
		[
			'methods'             => 'GET',
			'permission_callback' => '__return_true',
			'callback'            => 'elechouse_rfid_broker_auth_check',
		]
	);
} );

function elechouse_rfid_broker_auth_check( WP_REST_Request $request ) {
	nocache_headers();

	$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
	if ( ! in_array( $remote_addr, [ '127.0.0.1', '::1' ], true ) ) {
		return new WP_REST_Response(
			[
				'ok'    => false,
				'error' => 'local_only',
			],
			403
		);
	}

	$user_id = get_current_user_id();

	// WordPress REST cookie auth normally requires an X-WP-Nonce and may reset
	// current_user to 0 when no nonce is present. The Broker is a same-server
	// verifier that forwards the browser Cookie header, so validate the normal
	// front-end logged-in cookie manually instead of requiring a REST nonce.
	if ( ! $user_id ) {
		$user_id = wp_validate_auth_cookie( '', 'logged_in' );
	}

	if ( ! $user_id ) {
		return new WP_REST_Response(
			[
				'ok'        => false,
				'logged_in' => false,
			],
			401
		);
	}

	wp_set_current_user( (int) $user_id );
	$user = wp_get_current_user();

	return new WP_REST_Response(
		[
			'ok'        => true,
			'logged_in' => true,
			'user'      => [
				'id'           => (int) $user->ID,
				'login'        => (string) $user->user_login,
				'display_name' => (string) $user->display_name,
				'roles'        => array_values( (array) $user->roles ),
			],
		],
		200
	);
}
