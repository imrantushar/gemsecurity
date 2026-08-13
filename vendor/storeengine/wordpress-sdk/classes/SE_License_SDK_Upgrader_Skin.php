<?php

/**
 * Non-interactive Upgrader skin used by SE_License_SDK_Install_Job.
 *
 * Captures all feedback() and error() output into an array instead of
 * echoing HTML, so the REST handler can return it as JSON and the React
 * UI can render it in a log drawer.
 */
final class SE_License_SDK_Upgrader_Skin extends WP_Upgrader_Skin {

	/**
	 * @var array{level:string,message:string,time:int}[]
	 */
	private $messages = [];

	/**
	 * Capture WP_Error messages routed through error().
	 *
	 * @var string[]
	 */
	private $errors = [];

	/**
	 * @return array
	 */
	public function get_messages(): array {
		return $this->messages;
	}

	/**
	 * @return string[]
	 */
	public function get_errors(): array {
		return $this->errors;
	}

	public function get_last_error(): ?string {
		return $this->errors ? end( $this->errors ) : null;
	}

	public function header() {
		// Suppress HTML output.
	}

	public function footer() {
		// Suppress HTML output.
	}

	public function feedback( $feedback, ...$args ) {
		// WP_Upgrader_Skin::feedback supports both translation-string lookups
		// and pre-translated strings. Reuse its own resolver to get a final
		// string, then bypass the echo by capturing the output.
		if ( isset( $this->upgrader->strings[ $feedback ] ) ) {
			$feedback = $this->upgrader->strings[ $feedback ];
		}

		if ( ! empty( $args ) ) {
			$args = array_map( 'strip_tags', $args );
			$args = array_map( 'esc_html', $args );
			$feedback = vsprintf( $feedback, $args );
		}

		$feedback = trim( wp_strip_all_tags( $feedback ) );

		if ( '' === $feedback ) {
			return;
		}

		$this->messages[] = [
			'level'   => 'info',
			'message' => $feedback,
			'time'    => time(),
		];
	}

	public function error( $errors ) {
		if ( is_string( $errors ) ) {
			$this->errors[]   = $errors;
			$this->messages[] = [
				'level'   => 'error',
				'message' => $errors,
				'time'    => time(),
			];

			return;
		}

		if ( is_wp_error( $errors ) ) {
			foreach ( $errors->get_error_messages() as $message ) {
				$this->errors[]   = $message;
				$this->messages[] = [
					'level'   => 'error',
					'message' => $message,
					'time'    => time(),
				];
			}
		}
	}

	public function request_filesystem_credentials( $error = false, $context = '', $allow_relaxed_file_ownership = false ) {
		// REST handler can't prompt for FTP creds. Force the direct method.
		// If FS_METHOD isn't 'direct' on this host, WP_Filesystem() will
		// short-circuit and Install_Job reports a clear error to the UI.
		return true;
	}
}

// End of file SE_License_SDK_Upgrader_Skin.php.
