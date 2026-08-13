<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
	<div class="se-sdk-deactivation-modal--wrap reason">
		<div class="se-sdk-deactivation-modal--header">
			<h3>
				<?php if ( $this->client->getProductLogo() ) { ?>
					<img height="32" src="<?php echo esc_attr( $this->client->getProductLogo() ); ?>" alt="<?php echo esc_attr( $this->client->getPackageName() ); ?>">
				<?php } ?>
				<?php esc_html_e( 'Quick Feedback', 'storeengine-sdk' ); ?>
			</h3>
			<a href="javascript:void 0;" class="se-sdk-deactivation-modal--close" aria-label="<?php esc_attr_e( 'Close', 'storeengine-sdk' ); ?>">
				<svg aria-hidden="true" focusable="false" viewBox="0 0 24 24">
					<path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"></path>
				</svg>
			</a>
		</div>
		<div class="se-sdk-deactivation-modal--body">
			<div class="feedback-message">
				<?php printf(
						__( 'If you have a moment, please let us know why you are deactivating %s.', 'storeengine-sdk' ),
					'<strong>' . esc_html( $this->client->getPackageName() ) . '</strong>',
				); ?>
			</div>
			<div class="se-sdk-deactivation-modal--open-ticket">
				<span><?php esc_html_e( 'If you face any issues, please create a support ticket', 'storeengine-sdk' ); ?></span>
				<button class="open-ticket-form">
					<?php esc_html_e( 'Open a Ticket', 'storeengine-sdk' ); ?>
					<svg width="6" height="10" viewBox="0 0 6 10" fill="none" xmlns="http://www.w3.org/2000/svg">
						<path d="M0.528636 0.528636C0.788986 0.268287 1.211 0.268287 1.47134 0.528636L5.47134 4.52864C5.73169 4.78899 5.73169 5.211 5.47134 5.47134L1.47134 9.47134C1.211 9.7317 0.788986 9.7317 0.528636 9.47134C0.268287 9.211 0.268287 8.78899 0.528636 8.52864L4.05728 4.99999L0.528636 1.47134C0.268287 1.211 0.268287 0.788986 0.528636 0.528636Z"/>
					</svg>
				</button>
			</div>
			<ul class="reasons">
				<?php foreach ( $reasons as $reason ) { ?>
					<li class="reason-item" data-type="<?php echo esc_attr( $reason['type'] ); ?>" data-placeholder="<?php echo esc_attr( $reason['placeholder'] ); ?>">
						<label>
							<input class="reason-type" type="radio" name="selected-reason" value="<?php echo esc_attr( $reason['id'] ); ?>"> <?php echo esc_html( $reason['text'] ); ?>
						</label>
					</li>
				<?php } ?>
			</ul>
		
		</div>
		<div class="se-sdk-deactivation-modal--footer">
			<button class="button deactivate"><?php esc_html_e( 'Submit & Deactivate', 'storeengine-sdk' ); ?></button>
			<button class="button button-link dont-bother-me"><?php esc_html_e( 'Skip & Deactivate', 'storeengine-sdk' ); ?></button>
		</div>
	</div>
<?php
