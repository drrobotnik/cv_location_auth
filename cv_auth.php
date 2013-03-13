<?php /*

**************************************************************************

Plugin Name:  CV Location Authenticate
Plugin URI:   http://comingsoon.com
Description:  Additional security layer to the authentication process.
Version:      1.1.2
Author:       Brandon Lavigne
Author URI:   http://caavadesign.com
License:      GPLv2 or later


**************************************************************************/
global $pagenow;
require_once(__DIR__.'/helpers.php');

add_action('init','cv_check_nonce');

add_action('wp_login','cv_authenticate');

