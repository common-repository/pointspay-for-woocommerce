<?php

/**
 * Pointspay Payment Gateway
 *
 * @description Provides Pointspay Payment Gateway for WooCommerce.
 *
 * @class WC_Gateway_Pointspay
 * @package WooCommerce
 * @category Payment Gateways
 * @author Gaurav Agrawal
 */

if (!defined('ABSPATH')) {
	exit; // Exit if accessed directly
}

class WC_Gateway_Pointspay extends WC_Payment_Gateway
{

	/**
	 * __construct function.
	 *
	 * @since 1.0.0
	 * @access public
	 * @return void
	 */
	public function __construct()
	{
		global $woocommerce;

		$this->id = 'pointspay';
		$this->method_title = __('Pointspay', 'pointspay');
		$this->method_description = __('Accept payments using Pointspay.', 'pointspay');
		$this->has_fields = false;
		$this->liveurl = 'https://secure.pointspay.com';
		$this->testurl = 'https://uat-secure.pointspay.com';
		$this->supports = ['products', 'refunds'];

		// Load the form fields
		$this->init_form_fields();

		// Load the settings ( built-in )
		$this->init_settings();

		// Create a logger
		$this->logger = class_exists('WC_Logger') ? new WC_Logger() : $woocommerce->logger();

		// Load parameter from settings
		$this->enabled = $this->settings['enabled'];
		$this->testmode = $this->settings['testmode'];
		$this->title = $this->settings['title'];
		$this->description = $this->settings['description'];
		$this->cancel_url = $this->settings['cancel_url'];
		$this->username = $this->settings['username'];
		$this->password = $this->settings['password'];
		$this->access_token = $this->settings['access_token'];
		$this->merchant_code = $this->settings['merchant_code'];
		$this->private_key = $this->settings['private_key'];

		// Load dynamic options
		$this->icon = $this->get_base_url() . '/checkout/user/btn-img?s=' . $this->merchant_code;
		$this->currency = $this->get_currency();
		$language = explode('-', get_bloginfo('language'));
		$this->language = end($language);

		// Return URL for Redirect
		$this->redirect_url = add_query_arg('wc-api', $this->id, home_url());

		// Admin options
		add_action('woocommerce_update_options_payment_gateways_' . $this->id, array($this, 'process_admin_options'));

		// API Callback - IPN / Redirect
		add_action('woocommerce_api_' . $this->id, array($this, 'handle_callback'));
	} // End Constructor


	/**
	 * Initialises Gateway Settings Form Fields
	 *
	 * @since 1.0.0
	 * @return void
	 */
	function init_form_fields()
	{
		$this->form_fields = array(
			'basic_settings' => array(
				'title' => __('Basic Settings', 'pointspay'),
				'type' => 'title',
			),
			'enabled' => array(
				'title' => __('Enable/Disable', 'pointspay'),
				'type' => 'checkbox',
				'label' => __('Enable Pointspay Payment Gateway', 'pointspay'),
				'default' => 'yes'
			),
			'testmode' => array(
				'title' => __('Test Mode', 'pointspay'),
				'type' => 'checkbox',
				'label' => __('Enable Pointspay Test Environment. If checked, please make sure you use test keys for Access Settings below.', 'pointspay'),
				'default' => 'no'
			),
			'title' => array(
				'title' => __('Title', 'pointspay'),
				'type' => 'text',
				'description' => __('Payment method title that the customers see during the checkout.', 'pointspay'),
				'default' => __('Pointspay', 'pointspay')
			),
			'description' => array(
				'title' => __('Description', 'pointspay'),
				'type' => 'textarea',
				'description' => __('Payment method description that the customers see during the checkout.', 'pointspay'),
				'default' => __('Pay with Pointspay', 'pointspay'),
			),
			'cancel_url' => array(
				'title' => __('Cancel URL', 'pointspay'),
				'type' => 'url',
				'description' => __('Redirect customers to this URL upon payment cancellation.', 'pointspay'),
			),
			'access_settings' => array(
				'title' => __('Access Settings', 'pointspay'),
				'type' => 'title',
			),
			'username' => array(
				'title' => __('API Username', 'pointspay'),
				'type' => 'text',
				'description' => __('API Username is generated at the time of activation of your site and helps to uniquely identify you to Pointspay.', 'pointspay'),
				'default' => ''
			),
			'password' => array(
				'title' => __('API Password', 'pointspay'),
				'type' => 'password',
				'description' => __('API Password is generated at the time of activation of your site and helps to validate your API Username.', 'pointspay'),
				'default' => ''
			),
			'access_token' => array(
				'title' => __('API Access Token', 'pointspay'),
				'type' => 'text',
				'description' => __('API Access Token is generated at the time of activation of your site and helps to validate callbacks with Pointspay.', 'pointspay'),
				'default' => ''
			),
			'merchant_code' => array(
				'title' => __('Merchant Code (Shop ID)', 'pointspay'),
				'type' => 'text',
				'description' => __('Merchant Code (Shop ID) is the unique identity of your WooCommerce Store, as registered with Pointspay.', 'pointspay'),
				'default' => ''
			),
			'private_key' => array(
				'title' => __('Private Key', 'pointspay'),
				'type' => 'textarea',
				'description' => __('Private Key is generated by you on your server, and is used for signing all requests sent to Pointspay.', 'pointspay'),
				'default' => ''
			),
		);
	} // End init_form_fields()


	/**
	 * Displays Admin Panel Options
	 *
	 * @since 1.0.0
	 * @access public
	 * @return void
	 */
	public function admin_options()
	{
		echo '<h3>' . esc_html($this->method_title) . '<small class="wc-admin-breadcrumb"><a href="' . admin_url('admin.php?page=wc-settings&tab=checkout') . '" aria-label="Return to payments">⤴</a></small>' . '</h3>';
		echo '<p>' . esc_html($this->method_description) . '</p>';
		echo '<p>Please setup your IPN (server to server call) URL as: <code>', esc_url($this->redirect_url), '&IPN=1</code> on your Pointspay account.</p>';
		if (current_user_can('manage_options')) {
			echo '<table class="form-table">';
			$this->generate_settings_html(); // Generate the HTML For the settings form
			echo '</table>';
		} else {
			wp_die('<b>' . __('ERROR: You do not have permissions to access settings for Pointspay payments gateway.', 'pointspay') . '</b>');
		}
	} // End admin_options()


	/**
	 * Returns the description for the payment gateway
	 *
	 * @since 1.0.0
	 * @access public
	 * @return string
	 */
	public function get_description()
	{
		return $this->description;
	} // End get_description()


	/**
	 * Returns the base URL depending on the mode
	 *
	 * @since 1.0.0
	 * @return string
	 */
	function get_base_url()
	{
		return ('yes' == $this->testmode) ? $this->testurl : $this->liveurl;
	} // End get_base_url()


	/**
	 * Return the current transaction currency
	 * - Supports WOOCS currency switcher
	 *
	 * @since 1.0.0
	 * @return string
	 */
	function get_currency()
	{
		if (class_exists('WOOCS')) {
			global $WOOCS;
			try {
				return strtoupper($WOOCS->storage->get_val('woocs_current_currency'));
			} catch (Exception $e) {
				$this->log_message('Error while getting currency: ' . $e->getMessage());
			}
		}
		return get_woocommerce_currency();
	} // End get_currency()


	/**
	 * Obtains OAuth token for the request
	 *
	 * @since 1.0.0.
	 * @return string|false
	 */
	function get_oauth_token()
	{
		// Use existing oauth token if not expired
		$access_token = get_transient('pointspay_oauth_token');

		if (empty($access_token)) {
			try {
				$params = array(
					'headers' => array(
						'Content-Type' => 'application/x-www-form-urlencoded',
						'Authorization' => 'Basic ' . base64_encode($this->username . ':' . $this->password),
						'Accept' => 'application/json',
					),
					'body' => array(
						'grant_type' => 'client_credentials'
					),
					'timeout' => 120,
					'sslverify' => false,
				);
				$url = $this->get_base_url() . '/checkout/oauth/token';
				$this->log_message("Requesting access token from $url with paramters", $params);

				// Obtain Oauth token from Pointspay using access credentials
				$response = wp_remote_post($url, $params);
				$data = $this->process_http_response($response);

				if (empty($data) || !is_array($data) || empty($data['access_token'])) {
					$this->log_message('Failed to obtain a valid access token', $response['body']);
				} else {
					$access_token = $data['access_token'];
					$validity = (int) $data['expires_in'];
					set_transient('pointspay_oauth_token', $access_token, $validity);
					$this->log_message('Access token fetched successfully', $access_token);
				}
			} catch (Exception $e) {
				$this->log_message('Error while fetching access token', $e->getMessage());
			}
		} else {
			$this->log_message('Using prefetched access token', $access_token);
		}

		return $access_token;
	} // End get_oauth_token()


	/**
	 * Validates request parameters for callbacks
	 *
	 * @since 1.0.0
	 * @return bool
	 */
	function validate_request_params()
	{
		$text = '';
		$params = ['status', 'msg', 'order', 'guid'];
		foreach ($params as $param) {
			$text .= $this->get_request_param($param) ?? '';
		}

		$hash = hash_hmac('md5', $text, $this->access_token);
		$this->log_message('Calculated Hash', $hash);

		return $hash === $this->get_request_param('hash');
	} // End validate_request_params()


	/**
	 * Process the callback from Pointspay
	 *
	 * @since 1.0.0
	 * @access public
	 * @return mixed
	 */
	public function process_callback()
	{
		// Check if order ID is included in the callback
		$order_id = (int) $this->get_request_param('order');
		if (empty($order_id)) {
			$this->log_message('Erroneous callback with empty Order ID');
			return -1;
		}

		// Validate the request parameters using MD5 hash
		if (!$this->validate_request_params()) {
			$this->log_message('Failed to validate request parameters');
			return -1;
		}

		// Validate the transaction ID as unique for the order
		$transaction_id = $this->get_request_param('guid');
		$stored_transaction_id = get_post_meta($order_id, 'pointspay_transaction_id', true);
		if (!empty($stored_transaction_id)) {
			if ($transaction_id != $stored_transaction_id) {
				$this->log_message("GUID doesn't match the stored transaction ID for Order ID $order_id");
				return -1;
			}
		}

		try {
			$status = strtolower($this->get_request_param('status'));
			$order = wc_get_order($order_id);
			$response = 1;

			// If the payment hasn't been processed already for this order
			if (empty($stored_transaction_id)) {
				$message = $this->get_request_param('msg');

				$order->add_order_note($message . __(' via Pointspay tranasaction ID ', 'pointspay') . $transaction_id);

				switch ($status) {
					case 'success':	// Payment completed successfully
						update_post_meta($order_id, 'pointspay_transaction_id', $transaction_id);
						$order->payment_complete();
						break;
					case 'failed':	// Payment failed
						$order->update_status('failed');
						break;
				}

				$this->log_message("Tranasction status is $status, note added to Order ID $order_id with message", $message);
			} else {
				// Payment already processed successfully
				$response = 0;
				$this->log_message("Order ID $order_id already has an associated transaction ID, the callback is ignored", $stored_transaction_id);
			}

			// If the order status is final then return order received URL, else payment URL
			return [$response, in_array($status, ['failed', 'success']) ? $this->get_return_url($order) : $order->get_checkout_payment_url()];
		} catch (Exception $e) {
			$this->log_message("Error while updating order status for Order ID $order_id to $status", $e->getMessage());
		}

		return -1;
	} // End process_callback()


	/**
	 * Check the validity of data recived and update the status of order
	 *
	 * @since 1.0.0
	 * @return void
	 */
	function handle_callback()
	{
		$this->log_message('handle_callback triggered with parameters', $_GET);
		$response = $this->process_callback();
		if (-1 === $response) {
			echo 'FAILURE';
		} else {
			list($code, $url) = $response;
			if (empty($this->get_request_param('IPN'))) {
				// Processing a redirect
				$this->log_message('Redirecting to', $url);
				wp_safe_redirect(esc_url_raw($url));
			} else {
				// Processing IPN
				echo esc_attr($code) ? 'SUCCESS' : 'IGNORED';
			}
		}
		exit;
	} // End handle_callback()


	/**
	 * Obtains the payment redirect URL for the order
	 *
	 * @since 1.0.0
	 * @param int	order_id	Order id for which redirect URL has to be fetched
	 * @return string|WP_Error
	 */
	function fetch_payment_url($order_id)
	{
		try {
			$order = wc_get_order($order_id);

			$data = array(
				'amount' => sprintf("%0.2f", $order->get_total()),
				'currency' => $order->get_currency(),
				'language' => $this->language,
				'merchant_code' => $this->merchant_code,
				'merchant_order' => strval($order_id),
				'redirect_urls' => array(
					'cancel' => trim($this->cancel_url ?? '') ?: $order->get_checkout_payment_url(),
					'fail' => $this->redirect_url,
					'success' => $this->redirect_url,
				),
				'timestamp' => strval(round(microtime(true) * 1000)),
				'type' => 'direct',
			);

			$this->log_message("Fetching Payment URL for Order ID $order_id");

			// Fetch the payment URL
			$url = $this->get_base_url() . '/checkout/services/v3/transactions';
			$response = $this->post_data($url, $data);

			$status = $response['status'];
			$links = $response['links'];
		} catch (Exception $e) {
			$this->log_message($e->getMessage());
			return new WP_Error('pointspay', 'Failed to connect with payment gateway');
		}

		// If the payment transaction is not accepted by the gateway
		if ('accepted' !== $status) {
			$this->log_message("Received transaction status: $status");
			return new WP_Error('pointspay', 'Transaction not accepted by the payment gateway');
		}

		// Fetch the payment URL from links in the response
		$payment_url = false;
		foreach ($links as $link) {
			if ('payment' === $link['rel'] && 'REDIRECT' === $link['method']) {
				$payment_url = $link['href'] ?? false;
				break;
			}
		}

		// If payment URL is not found among the links
		if (!$payment_url) {
			return new WP_Error('pointspay', 'Payment URL not returned by the payment gateway');
		}

		return $payment_url;
	} // End fetch_payment_url()


	/**
	 * Process the payment and return the result.
	 *
	 * @since 1.0.0
	 * @access public
	 * @param int	order_id	Order id for which payment is being made
	 * @return array
	 */
	public function process_payment($order_id)
	{
		$url = $this->fetch_payment_url($order_id);

		// If any error occurred while fetching the payment URL
		if (is_wp_error($url)) {
			$message = $url->get_error_message();
			$this->log_message("Error while fetching payment URL for Order ID $order_id: $message");
			wc_add_notice($message, 'error');
			return;
		}

		$this->log_message("Redirecting to payment url for Order ID $order_id - $url");

		return array(
			'result' 	=> 'success',
			'redirect'	=> $url
		);
	} // End process_payment()


	/**
	 * Process the refund
	 * 
	 * @since 1.0.0
	 * @access public
	 * @param int		order_id	ID of the order to be refunded
	 * @param float		amount		Amount to be refunded
	 * @param string	reason		Reason for the refund
	 * @return bool
	 */
	public function process_refund($order_id, $amount = 0, $reason = '')
	{
		$this->log_message("Requested refund of $amount towards Order ID $order_id", $reason);

		try {
			// Validate order
			$order = wc_get_order($order_id);
			if (empty($order)) {
				throw new Exception(__('Could not locate order with Order ID', 'pointspay'));
			}

			// Validate payment method
			if ($this->id !== $order->get_payment_method()) {
				throw new Exception(__('Order cannot be refunded using a different payment method', 'pointspay'));
			}

			// Validate transaction id
			$transaction_id = get_post_meta($order_id, 'pointspay_transaction_id', true);
			if (empty($transaction_id)) {
				throw new Exception(__('Pointspay transaction ID could not be located for the order', 'pointspay'));
			}

			// Validate amount
			if ($amount <= 0) {
				throw new Exception(__('Cannot refund non-positive amount', 'pointspay'));
			}
			$total = $order->get_total();
			if ($amount > $total) {
				throw new Exception(__('Requested refund amount exceeds order total', 'pointspay'));
			}

			// Formulate the parameters
			$data = array(
				'amount' => sprintf("%0.2f", $amount),
				'currency' => $order->get_currency(),
				'timestamp' => strval(round(microtime(true) * 1000)),
			);

			// Make the request and process the response
			$url = $this->get_base_url() . '/checkout/services/v3/transactions/' . $transaction_id . '/refunds';
			$response = $this->post_data($url, $data);

			$status = $response['status'];
			$message = $response['status_message'] ?? $response[$status . 'Message'] ?? '';
			$refund_id = $response['id'] ?? false;

			// Add order note
			$note = $message . __(' Pointspay refund ID: ', 'pointspay') . $refund_id . __(' Amount: ', 'pointspay') . wc_price($amount);
			if (!empty($reason)) {
				$note .= __(' Reason: ', 'pointspay') . $reason;
			}
			$order->add_order_note($note);

			// Add refund ID to order if refund was successful
			if ('success' === $status && $refund_id) {
				add_post_meta($order_id, 'pointspay_refund_id', $refund_id, false);
				$this->log_message($message . ' Order ID', $order_id);
			} else {
				throw new Exception($message);
			}
		} catch (Exception $e) {
			$this->log_message($e->getMessage());
			throw $e;
		}

		return true;
	} // End process_refund()


	/**
	 * Calculates signature for the message body
	 *
	 * @since 1.0.0
	 * @param string	text	Contents to calculate signature for
	 * @return string
	 */
	function calculate_signature($text)
	{
		$this->log_message('Obtaining encryption key from Private Key');
		if (empty($this->private_key)) {
			throw new Exception('Private Key is empty');
		}

		// Read stored private key
		$key = openssl_pkey_get_private($this->private_key);
		if (empty($key)) {
			throw new Exception('Private Key could not be decoded');
		}

		// Calculate SHA256 digest for the text to be encrypted
		$this->log_message('Calculating digest hash for body');
		$digest = openssl_digest($text, 'sha256', true);
		if (empty($digest)) {
			throw new Exception('Failed to digest post body');
		}

		// Encrypt digesh hash
		$this->log_message('Encrypting digest hash using private key');
		if (openssl_private_encrypt($digest, $hash, $key)) {
			// Encode using Base64 to get the signature
			$signature = base64_encode($hash);
		} else {
			throw new Exception('Failed to encrypt digest hash using private key');
		}

		return $signature;
	} // End calculate_signature()


	/**
	 * Creates the headers for authorization with Pointspay
	 *
	 * @since 1.0.0
	 * @param string	body	Post payload to be used for calculating hash
	 * @return array
	 */
	function create_headers($body = '')
	{
		// Calculate signature from the given request body
		$this->log_message('Obtaining signature');
		$signature = $this->calculate_signature(preg_replace("/\s+/", '', $body));
		if (empty($signature)) {
			throw new Exception('calculate_signature failed');
		}

		// Fetch Oauth token
		$this->log_message('Obtaining oauth token');
		$authorization = $this->get_oauth_token();
		if (empty($authorization)) {
			throw new Exception('get_oauth_token failed');
		}

		// Return the headers array
		return [
			'Content-Type' => 'application/json',
			'Authorization' => 'Bearer ' . $authorization,
			'Signature' => $signature,
			'Accept' => 'application/json',
		];
	} // End create_headers()


	/**
	 * Parse HTTP response and returns relevant data
	 *
	 * @since 1.0.0
	 * @param array	response	Response received from HTTP request
	 * @return array
	 */
	function process_http_response($response)
	{
		$this->log_message('Processing Response', $response);

		// If an error is occurred throw an exception
		if (is_wp_error($response)) {
			throw new Exception($response->get_error_message());
		}

		// Decode the body if it's a JSON string
		$body = is_array($body) ? $body : json_decode($response['body'], true);

		// Validate teh response code
		$response = $response['response'];
		$code = (int) $response['code'] ?: 200;
		if (200 < $code || $code >= 300) {
			$message = "HTTP $code - {$response['message']}";
			if (is_array($body) && !empty($body['message'])) {
				$message .= ': ' . $body['message'];
			}
			throw new Exception($message);
		}

		// If the JSON decoding failed, throw an exception
		if (null === $body) {
			throw new Exception(json_last_error_msg());
		}

		return $body;
	} // End process_http_response()


	/**
	 * Gets the remote data
	 *
	 * @since 1.0.0
	 * @param string	url			Request url
	 * @return array
	 */
	function get_data($url)
	{
		// Calculate headers
		$headers = $this->create_headers();
		if (empty($headers)) {
			throw new Exception('Failed to create headers for get_data');
		}

		// Obtain the contents via wp_remote_get
		$options =  array(
			'headers' => $headers,
			'timeout' => 120,
			'sslverify' => false,
		);

		$this->log_message("Getting $url with options", $options);

		$response = wp_remote_get($url, $options);

		// Process the HTTP response
		return $this->process_http_response($response);
	} // End get_data()


	/**
	 * Puts the data to remote URL and returns the response
	 *
	 * @since 1.0.0
	 * @param string	url 		Request url
	 * @param array		data 		Data to be posted to the URL
	 * @return array
	 */
	function post_data($url, $data)
	{
		// JSON encode the data
		$body = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
		if (empty($body)) {
			throw new Exception('Failed to JSON encode data');
		}
		$body = stripcslashes($body);

		// Calculate headers given the body text (JSON)
		$headers = $this->create_headers($body);
		if (empty($headers)) {
			throw new Exception('Failed to create headers for post_data');
		}

		// Obtain the contents via wp_remote_post
		$params = array(
			'headers' => $headers,
			'timeout' => 120,
			'sslverify' => false,
			'body' => $body,
		);

		$this->log_message("Posting to $url with parameters", $params);

		$response = wp_remote_post($url, $params);

		// Process the HTTP response
		return $this->process_http_response($response);
	} // End post_data()


	/**
	 * Get request data if set
	 *
	 * @since 1.0.0
	 * @param string	name	Name of the variable to be obtained
	 * @return mixed
	 */
	function get_request_param($name)
	{
		return isset($_REQUEST[$name]) ? sanitize_text_field($_REQUEST[$name]) : null;
	} // End get_request_param()


	/**
	 * Log a message to log file
	 *
	 * @since 1.0.0
	 * @param string	message	Message to be logged
	 * @param mixed		data	Additional data to be logged as json encoded string
	 * @param string	sep		Separator to be used for appending data to message
	 * @return void
	 */
	function log_message($message, $data = null, $sep = ': ')
	{
		if (!empty($data)) {
			$message .= $sep;
			if (is_wp_error($data)) {
				$message .= $data->get_error_message();
			} elseif (is_string($data)) {
				$message .= esc_html($data);
			} else {
				$message .= esc_html(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
			}
		}
		$this->logger->add($this->id, stripcslashes($message));
	} // End log_message()

}; //  End Class
