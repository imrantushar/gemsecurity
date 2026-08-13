<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
	<div class="se-sdk-deactivation-modal--wrap support" style="display: none;">
		<div class="se-sdk-deactivation-modal--header">
			<h3><?php esc_html_e( 'Submit Support Ticket', 'storeengine-sdk' ); ?></h3>
			<a href="javascript:void 0;" class="se-sdk-deactivation-modal--close" aria-label="<?php esc_attr_e( 'Close', 'storeengine-sdk' ); ?>">
				<svg aria-hidden="true" focusable="false" viewBox="0 0 24 24">
					<path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"></path>
				</svg>
			</a>
		</div>
		<div class="se-sdk-deactivation-modal--body">
			<div class="se-sdk-row mui col-2 col-left">
				<label for="<?php echo esc_attr( $slug ); ?>-se-sdk-support--name" class="<?php echo ! empty( $displayName ) ? 'shrink' : ''; ?>"><?php esc_html_e( 'Name', 'storeengine-sdk' ); ?></label>
				<div class="se-sdk-form-control">
					<input type="text" name="name" id="<?php echo esc_attr( $slug ); ?>-se-sdk-support--name" value="<?php echo esc_attr( $displayName ); ?>" required>
				</div>
			</div>
			<div class="se-sdk-row mui col-2 col-right">
				<label for="<?php echo esc_attr( $slug ); ?>-se-sdk-support--email" class="shrink"><?php esc_html_e( 'Email', 'storeengine-sdk' ); ?></label>
				<div class="se-sdk-form-control">
					<input type="email" name="email" id="<?php echo esc_attr( $slug ); ?>-se-sdk-support--email" value="<?php echo esc_attr( $admin_user->user_email ); ?>" required>
				</div>
			</div>
			<div class="clear"></div>
			<div class="se-sdk-row mui col-2 col-left">
				<label for="<?php echo esc_attr( $slug ); ?>-se-sdk-support--subject"><?php esc_html_e( 'Subject', 'storeengine-sdk' ); ?></label>
				<div class="se-sdk-form-control">
					<input type="text" name="subject" id="<?php echo esc_attr( $slug ); ?>-se-sdk-support--subject" required>
				</div>
			</div>
			<div class="se-sdk-row mui col-2 col-right">
				<label for="<?php echo esc_attr( $slug ); ?>-se-sdk-support--website" class="shrink"><?php esc_html_e( 'Website', 'storeengine-sdk' ); ?></label>
				<div class="se-sdk-form-control">
					<input type="url" name="website" id="<?php echo esc_attr( $slug ); ?>-se-sdk-support--website" value="<?php echo esc_url( site_url() ); ?>" required>
				</div>
			</div>
			<div class="clear"></div>
			<div class="se-sdk-row mui">
				<label for="<?php echo esc_attr( $slug ); ?>-se-sdk-support--message"><?php esc_html_e( 'Message', 'storeengine-sdk' ); ?></label>
				<div class="se-sdk-form-control">
					<textarea id="<?php echo esc_attr( $slug ); ?>-se-sdk-support--message" name='message' rows="11" required></textarea>
				</div>
			</div>
			<div class="response">
				<div class="wrapper"></div>
			</div>
		</div>
		<div class="se-sdk-deactivation-modal--footer">
			<button class="button send-ticket"><?php esc_html_e( 'Send Message', 'storeengine-sdk' ); ?></button>
			<button class="button button-link close-ticket"><?php esc_html_e( 'Cancel', 'storeengine-sdk' ); ?></button>
		</div>
	</div>
<?php
