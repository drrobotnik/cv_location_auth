<?php 

function cv_authenticate($user){
	$user_key = cv_check_location($user);

	if ( is_wp_error($user_key) ){
		echo $user_key->get_error_message();die;
	}

}

function cv_check_nonce(){
	$nonce = $_REQUEST['_wpnonce'];
	$user = $_REQUEST['user_login'];
	$action =  $_REQUEST['action'];
	if( !empty($nonce) && $action == 'cv_verify' ){
		$location_set = cv_set_location_key($nonce,$user);
		if ( is_wp_error($location_set) ){
			echo $location_set->get_error_message();
		}else{
			return true;
		}
	}
}

function cv_check_location($user){

	$prefix = 'cv_';
	
	$user_details = cv_build_user_key($user);

	if ( false === ( $recent_login_location = get_transient( $user_details->user_key ) ) ) {
		// It wasn't there, so regenerate the data and save the transient

		if(!empty($user_details)){
			$nonce = wp_create_nonce($prefix.'_'.$user.'_'.sanitize_key( getRealIpAddr() ));

			cv_send_location_nonce($user_details, $nonce);

		}else{
			return new WP_Error('No User Info Found', __("For some reason your user information doesn't match any account details. Either create an account, or if this is a mistake, contact the site administrator."));
		}

		return new WP_Error('newlocation', __("You haven't logged in from this location (". getRealIpAddr().") in awhile. An email has been sent to your account. Click the link within that email to continue to be logged in."));
	
	}

}

function cv_set_location_key($nonce,$user){
	$prefix = 'cv_';
	if (! wp_verify_nonce( $nonce, $prefix.'_'.$user.'_'.sanitize_key( getRealIpAddr() ) ) ) return new WP_Error('invalid key', __("Security measure failed for ".$user." at address: ". getRealIpAddr()));
	$expiration = 60*60*24*30; // 30 days.
	$validate_user = get_transient('verify_'.$nonce);
	if ( !empty( $validate_user ) ) {
		$user_details = cv_build_user_key($validate_user);
		set_transient( $user_details->user_key,1, $expiration);
	}

	return 1;

}

function cv_build_user_key($email_or_login){
	
	$format = ( is_email( $email_or_login ) ) ? 'email' : 'login';

	$user_data = get_user_by( $format, $email_or_login );

	$user_data->user_key = $prefix.$user.'_'.sanitize_key(getRealIpAddr());

	return $user_data;
	
}

function cv_send_location_nonce($user_details,$nonce){

	$user_email = $user_details->data->user_email;
	$user_login = $user_details->data->user_login;
	$site_name = get_option( 'blogname' );

	$expiration = 60*60*24; // 24 hours.

	$plugin_url = plugin_dir_url( __FILE__ );
	$verify_url = wp_login_url().'?action=cv_verify&_wpnonce='.$nonce.'&user_login='.$user_login;

	$headers[] = 'From: '.$site_name.' <me@example.net>';
	//$headers[] = 'Cc: John Q Codex <jqc@wordpress.org>';
	//$headers[] = 'Cc: iluvwp@wordpress.org'; // note you can just use a simple email address

	$subject = 'Verification - Login From New Location';
	$message = "<p>Someone has attempted to log-in using your account credentials from a new location. ";
	$message.= "As a safety precaution we require log-in attempts from new locations to verify through email. ";
	$message.= "After clicking the following link you'll grant access from this new location and you'll be asked to log-in again.";
	$message.= "If it was not you, ignore the link below.</p>";

	$message .= '<p><a href="'.$verify_url.'">'.$verify_url.'</a></p>';
	add_filter( 'wp_mail_content_type', function(){ return 'text/html'; } );
	$send = wp_mail( $user_email, $subject, $message, $headers );

	if ( !is_wp_error($send) && !empty($send) )
		set_transient( 'verify_'.$nonce, $user_email, $expiration );

}

function getRealIpAddr(){
	if (!empty($_SERVER['HTTP_CLIENT_IP'])) { //check ip from share internet
		$ip=$_SERVER['HTTP_CLIENT_IP'];
	} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) { //to check ip is pass from proxy
		$ip=$_SERVER['HTTP_X_FORWARDED_FOR'];
	}else{
		$ip=$_SERVER['REMOTE_ADDR'];
	}
	return $ip;
}