<?php

/**
 * Plugin Name: Pointspay for WooCommerce
 * Plugin URI: https://pointspay.com/woocommerce-plugin
 * Description: This plugin integrates Pointspay API for Payments and Refunds with WooCommerce.
 * Author: Pointspay
 * Author URI: https://pointspay.com
 * Version: 1.1.1
 * Text Domain: pointspay
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) {
	exit; // Exit if accessed directly
}

// WooCommerce is required for the plugin
if (in_array('woocommerce/woocommerce.php', (array) get_option('active_plugins', array()))) {
	// Init Pointspay Gateway after WooCommerce has loaded
	add_action('plugins_loaded', 'init_pointspay_gateway', 0);
} else {
	add_action('admin_notices', 'show_pointspay_wc_required_notice');
}

/**
 * init_pointspay_gateway function.
 *
 * @description Initializes the gateway.
 * @access public
 * @return void
 */
function init_pointspay_gateway()
{
	// If the WooCommerce payment gateway class is not available, do nothing
	if (!class_exists('WC_Payment_Gateway')) return;

	// Localization
	load_plugin_textdomain('pointspay', false, basename(dirname(__FILE__)) . '/languages/');

	// Core class for Payment gateway
	require_once(plugin_basename('classes/wc-gateway-pointspay.php'));

	// Add the gateway to list of available gateways
	add_filter('woocommerce_payment_gateways', 'add_pointspay_gateway');

	// Add setting link to the plugin
	add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'show_pointspay_plugin_links');
}

/**
 * add_pointspay_gateway function
 *
 * Register the gateway within WooCommerce.
 *
 * @since 1.0.0
 * @param array	methods	Available payment gateway methods
 * @return array
 */
function add_pointspay_gateway($methods)
{
	$methods[] = 'WC_Gateway_Pointspay';
	return $methods;
}

/**
 * show_pointspay_plugin_links function
 * 
 * Displays plugin settings link in the plugin listing
 * 
 * @since 1.0.0
 * @param array	links	Links currently being displayed below the plugin
 * @return array
 */
function show_pointspay_plugin_links($links)
{
	$links[] = '<a href="' . esc_url(admin_url('admin.php?page=wc-settings&tab=checkout&section=pointspay')) . '">' . __('Configure', 'pointspay') . '</a>';
	$links[] = '<a href="' . esc_url(admin_url('admin.php?page=wc-status&tab=logs&log_file=') . esc_attr('pointspay') . '-' . date('Y-m-d') . '-' . sanitize_file_name(wp_hash('pointspay')) . '.log') . '">' . __("Today's Logs", 'pointspay') . '</a>';
	return $links;
}


/**
 * Show admin notice regarding WC requirement
 * 
 * @since 1.0.0
 */
function show_pointspay_wc_required_notice()
{
	echo '<div class="notice notice-error"><h3>', __('Pointspay', 'pointspay'), '</h3><p>', __('Pointspay payment gateway requires WooCommerce to be installed and active.', 'pointspay'), '</p></div>';
	deactivate_plugins(plugin_basename(__FILE__));
}
