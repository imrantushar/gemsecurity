<?php
/**
 * @see SE_License_SDK_License::render_license_page()
 * @var SE_License_SDK_License $this
 * @var string $status
 * @var string $action
 * @var string $submit_label
 * @var string $status_label
 * @var bool $isUnlimited
 * @var int $remaining
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
	<div class="se-sdk-product-<?php echo esc_attr( $this->client->getSlug() ); ?> se-sdk-license-settings"
		 style="--se-sdk-primary-color: <?php echo esc_attr( $this->client->getPrimaryColor() ); ?>;">
		<div class="se-sdk-license-section">
			<div class="se-sdk-license-details">
				<div class="se-sdk-license-details-contents">
					<h3><?php echo wp_kses_post( $this->header_message ); ?></h3>
					<?php echo wp_kses_post( wpautop( $this->header_content ) ); ?>
				</div>
				<?php if ( $this->client->getProductLogo() ) { ?>
					<div class="se-sdk-license-details--middle-icons" aria-hidden="true">
						<img height="24" src="<?php echo esc_attr( $this->client->getProductLogo() ); ?>"
							 alt="<?php echo esc_attr( $this->client->getPackageName() ); ?>">
						<svg width="24" height="24" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
							<path fill="#A2ADB9"
								  d="M5.21227 4.00487C5.64135 4.0356 6.05888 4.15849 6.43639 4.36474C6.81391 4.57099 7.14259 4.8562 7.40026 5.20068C7.56556 5.42175 7.52066 5.73497 7.29967 5.90038C7.07855 6.06579 6.76488 6.02043 6.59948 5.79931C6.42771 5.56972 6.20852 5.37965 5.9569 5.24218C5.70526 5.10472 5.42698 5.02292 5.14098 5.00243C4.85497 4.98195 4.56785 5.02333 4.29918 5.12353C4.06402 5.21125 3.84772 5.34244 3.66149 5.50976L3.58336 5.58349L2.08971 7.07714L2.02331 7.14941C1.70093 7.51765 1.52392 7.9927 1.52819 8.48437C1.53281 9.00868 1.74336 9.51009 2.11413 9.88085C2.48489 10.2516 2.9863 10.4622 3.51061 10.4668C4.035 10.4713 4.54063 10.2696 4.91784 9.90526L5.76647 9.05663C5.96173 8.86137 6.27824 8.86137 6.4735 9.05663C6.66867 9.2519 6.66873 9.56843 6.4735 9.76366L5.61852 10.6186L5.50426 10.7241C4.95194 11.2076 4.23975 11.4731 3.50231 11.4668C2.71573 11.46 1.96332 11.1441 1.40709 10.5879C0.85087 10.0317 0.535023 9.27926 0.528188 8.49267C0.521818 7.75522 0.787322 7.04305 1.27086 6.49071L1.37633 6.37646L2.87633 4.87646L2.99303 4.76562C3.27237 4.51467 3.59686 4.31809 3.94957 4.18651C4.35258 4.03619 4.78324 3.97416 5.21227 4.00487ZM8.49791 0.533194C9.28447 0.540055 10.0369 0.855899 10.5931 1.4121C11.1493 1.96831 11.4647 2.72079 11.4715 3.50732C11.4783 4.29377 11.1761 5.05143 10.6298 5.61718L10.2596 5.25976L10.2699 5.27001L10.6298 5.61718L9.1234 7.12353C8.81929 7.42771 8.45316 7.66314 8.05016 7.81347C7.64718 7.96375 7.21646 8.02534 6.78747 7.99462C6.35842 7.96387 5.94082 7.84148 5.56334 7.63525C5.18588 7.429 4.85712 7.14375 4.59948 6.79931C4.43421 6.57819 4.47948 6.26497 4.70055 6.0996C4.92167 5.93424 5.23487 5.97956 5.40026 6.20068C5.57202 6.43028 5.79121 6.62032 6.04284 6.7578C6.29451 6.89531 6.57319 6.97706 6.85924 6.99755C7.14522 7.018 7.43241 6.97666 7.70104 6.87646C7.9697 6.77622 8.21365 6.61929 8.41637 6.4165L9.91637 4.9165C10.2769 4.53996 10.4761 4.03714 10.4715 3.51562C10.4669 2.99136 10.2568 2.48989 9.8861 2.11913C9.51528 1.74832 9.01352 1.53775 8.48913 1.53319C7.96473 1.52864 7.45959 1.7304 7.08239 2.09472L7.0819 2.09423L6.22741 2.94433C6.03158 3.13902 5.71507 3.1382 5.52038 2.94237C5.32576 2.74655 5.32655 2.43002 5.52233 2.23534L6.38268 1.38036L6.38756 1.37548C6.95337 0.829005 7.71132 0.526359 8.49791 0.533194Z"/>
						</svg>
						<svg width="24" height="24" viewBox="0 0 18 18" fill="none" xmlns="http://www.w3.org/2000/svg">
							<path fill="#738496"
								  d="M12.375 6C12.5821 6 12.75 5.83211 12.75 5.625C12.75 5.41789 12.5821 5.25 12.375 5.25C12.1679 5.25 12 5.41789 12 5.625C12 5.83211 12.1679 6 12.375 6Z"/>
							<path fill="#738496"
								  d="M6.75 12.7499C6.75003 12.3521 6.90818 11.9706 7.18945 11.6893C7.47075 11.408 7.85221 11.2499 8.25 11.2499H8.37891L8.45288 11.2462C8.62458 11.2291 8.78612 11.1532 8.90918 11.0301L9.52002 10.4193L9.60059 10.3497C9.77013 10.2227 9.98595 10.1728 10.1938 10.2135L10.2964 10.242L10.4626 10.2955C11.2982 10.5475 12.194 10.5285 13.0203 10.2384C13.9015 9.92897 14.6516 9.32959 15.1479 8.53843C15.6443 7.74726 15.8578 6.81074 15.7529 5.88267C15.648 4.95484 15.231 4.09011 14.5708 3.42979C13.9104 2.76942 13.0452 2.35261 12.1172 2.24766C11.1891 2.14276 10.2526 2.35555 9.46143 2.85191C8.67029 3.34824 8.07089 4.09841 7.76147 4.97959C7.45207 5.86085 7.4513 6.82146 7.75854 7.70347C7.85305 7.9751 7.78394 8.27719 7.58057 8.48057L2.46973 13.5907C2.34666 13.7137 2.27075 13.8753 2.25366 14.047L2.25 14.121V15.7499H4.5V14.9999C4.50003 14.6021 4.65818 14.2206 4.93945 13.9393C5.22075 13.658 5.6022 13.4999 6 13.4999H6.75V12.7499ZM12.375 5.24986C12.1679 5.24986 12.0001 5.41781 12 5.62486L12.0073 5.7003C12.0422 5.87133 12.1937 5.99986 12.375 5.99986C12.5563 5.99986 12.7078 5.87133 12.7427 5.7003L12.75 5.62486L12.7427 5.54942C12.7127 5.40289 12.597 5.28787 12.4504 5.25792L12.375 5.24986ZM8.25 13.4999C8.25 13.8977 8.09181 14.2791 7.81055 14.5604C7.52924 14.8417 7.14782 14.9999 6.75 14.9999H6V15.7499C6 16.1477 5.84181 16.5291 5.56055 16.8104C5.27924 17.0917 4.89782 17.2499 4.5 17.2499H2.25C1.85218 17.2499 1.47076 17.0917 1.18945 16.8104C0.908186 16.5291 0.75 16.1477 0.75 15.7499V14.121C0.750127 13.5243 0.987236 12.952 1.40918 12.5301L6.20288 7.7357C5.92982 6.66452 5.9779 5.53273 6.34644 4.48301C6.76835 3.2813 7.58567 2.25801 8.66455 1.58116C9.74338 0.904418 11.0202 0.61415 12.2856 0.757182C13.5511 0.900267 14.7308 1.46801 15.6313 2.36851C16.5319 3.26903 17.1003 4.44876 17.2434 5.71421C17.3864 6.97967 17.0954 8.25649 16.4187 9.33531C15.7418 10.4142 14.7186 11.2315 13.5168 11.6534C12.4668 12.0221 11.3349 12.0696 10.2634 11.7962L9.96973 12.0907C9.60062 12.4599 9.11654 12.6876 8.60156 12.7389L8.37891 12.7499H8.25V13.4999ZM13.5 5.62486C13.5 6.24618 12.9963 6.74986 12.375 6.74986C11.7925 6.74986 11.3134 6.30721 11.2559 5.73985L11.25 5.62486L11.2559 5.50987C11.3135 4.94262 11.7925 4.49986 12.375 4.49986L12.49 4.50572C13.0573 4.56331 13.4999 5.04241 13.5 5.62486Z"/>
						</svg>
					</div>
				<?php } ?>
				<div class="se-sdk-license-form-wrapper">
					<form method="post" id="<?php echo esc_attr( $this->client->getSlug() . '-license-form' ); ?>"
						  action="<?php $this->formActionUrl(); ?>" spellcheck="false" autocomplete="off">
						<?php wp_nonce_field( $this->data_key ); ?>
						<input type="hidden" name="<?php echo esc_attr( $this->data_key ); ?>[_action]"
							   value="<?php echo esc_attr( $action ); ?>">
						<div class="se-sdk-license-fields">
							<div class="input-group">
								<div class="license-input code">
									<label for="license_key"
										   class="screen-reader-text"><?php esc_html_e( 'License Key', 'storeengine-sdk' ); ?></label>
									<input class="se-sdk-license-fields--input regular-text" id="license_key"
										   type="text"
										   value="<?php echo esc_attr( $this->get_input_license_value( $this->license, $action ) ); ?>"
										   placeholder="<?php esc_attr_e( 'Enter your license key to activate', 'storeengine-sdk' ); ?>"
										   name="<?php echo esc_attr( $this->data_key ); ?>[license_key]"
											<?php wp_readonly( 'deactivate' === $action ); ?>
											<?php disabled( 'deactivate' === $action ); ?>
										   autocomplete="none"
										   required>
								</div>
							</div>
							<!-- /.se-sdk-license-fields .input-group -->
							<div class="input-group-inline">
								<button type="submit" name="<?php echo esc_attr( $this->data_key ); ?>[submit]"
										class="<?php echo esc_attr( $action ); ?>-button">
									<?php if ( 'activate' === $action ) { ?>
										<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"
											 viewBox="0 0 20 20" fill="none">
											<path d="M17.5 9.99992C17.5 5.85778 14.1421 2.49992 10 2.49992C5.85787 2.49992 2.50001 5.85778 2.50001 9.99992C2.50001 14.1421 5.85787 17.4999 10 17.4999C14.1421 17.4999 17.5 14.1421 17.5 9.99992ZM11.9108 7.74406C12.2363 7.41862 12.7638 7.41862 13.0892 7.74406C13.4146 8.0695 13.4146 8.59701 13.0892 8.92244L9.75587 12.2558C9.43043 12.5812 8.90292 12.5812 8.57748 12.2558L6.91082 10.5891C6.58538 10.2637 6.58538 9.73616 6.91082 9.41072C7.23625 9.08529 7.76377 9.08529 8.0892 9.41072L9.16668 10.4882L11.9108 7.74406ZM19.1667 9.99992C19.1667 15.0625 15.0626 19.1666 10 19.1666C4.9374 19.1666 0.833344 15.0625 0.833344 9.99992C0.833344 4.93731 4.9374 0.833252 10 0.833252C15.0626 0.833252 19.1667 4.93731 19.1667 9.99992Z"
												  fill="#F6F7F8"/>
										</svg>
									<?php } ?>
									<span><?php echo esc_html( $submit_label ); ?></span>
								</button>
								<?php if ( $this->manage_license_url ) { ?>
									<a href="<?php echo esc_url( $this->manage_license_url ); ?>"
									   class="dashboard-button" rel="noopener"
									   target="_blank"><?php esc_html_e( 'Manage License', 'storeengine-sdk' ); ?></a>
								<?php } ?>
							</div>
						</div>
					</form>

					<?php if ( 'active' !== $status && $this->client->get_purchase_url() ) { ?>
						<div class="se-sdk-license-purchase-prompt">
							<p>
								<?php
								printf(
								// translators: %s. Purchase link tag
										esc_html__( "Don’t have a license key? %s", 'storeengine-sdk' ),
										'<a href="' . esc_url( $this->client->get_purchase_url() ) . '" target="_blank" rel="noopener noreferrer">'
										. esc_html__( 'Purchase one here', 'storeengine-sdk' )
										. '</a>'
								);
								?>
							</p>
						</div>
					<?php } ?>

					<?php if ( 'active' === $status ) { ?>
						<div class="active-license-info">
							<div class="single-license-info license-status">
								<h3><?php esc_html_e( 'Status:', 'storeengine-sdk' ); ?></h3>
								<p class="<?php echo esc_attr( $status ); ?>"><?php echo esc_html( $status_label ); ?></p>
							</div>
							<?php if ( 'inactive' !== $status ) { ?>
								<div class="single-license-info license-checked_at">
									<h3><?php esc_html_e( 'Last Checked:', 'storeengine-sdk' ); ?></h3>
									<p class="<?php echo esc_attr( $status ); ?>">
										<?php $this->render_last_checked_datetime(); ?>
										<a href="<?php echo esc_url( add_query_arg( [ $this->client->getSlug() . '-check-license' => wp_create_nonce( $this->client->getSlug() ) ], $this->get_page_url() ) ); ?>">
											<span class="dashicons dashicons-update" aria-hidden="true"></span>
											<span class="screen-reader-text"><?php esc_html_e( 'Check License Status Now', 'storeengine-sdk' ); ?></span>
										</a>
									</p>
								</div>
							<?php } ?>
							<div class="single-license-info license-expires">
								<h3><?php esc_html_e( 'Expires: ', 'storeengine-sdk' ); ?></h3>
								<?php $this->render_license_expire_datetime(); ?>
							</div>
							<div class="single-license-info license-activation-count<?php echo $isUnlimited ? ' license-unlimited' : ''; ?>">
								<h3><?php esc_html_e( 'Activation Remaining: ', 'storeengine-sdk' ); ?></h3>
								<?php if ( 'active' === $status ) { ?>
									<?php if ( false !== $this->license['unlimited'] ) { ?>
										<p class="active">
											<?php
											$unlimited = '<i aria-hidden="true">';
											$unlimited .= '<svg style="top:2px;fill:currentColor;position:relative;" width="15px" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 512">';
											$unlimited .= '<!-- Font Awesome Free 5.15.4 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free (Icons: CC BY 4.0, Fonts: SIL OFL 1.1, Code: MIT License) -->';
											$unlimited .= '<path d="M471.1 96C405 96 353.3 137.3 320 174.6 286.7 137.3 235 96 168.9 96 75.8 96 0 167.8 0 256s75.8 160 168.9 160c66.1 0 117.8-41.3 151.1-78.6 33.3 37.3 85 78.6 151.1 78.6 93.1 0 168.9-71.8 168.9-160S564.2 96 471.1 96zM168.9 320c-40.2 0-72.9-28.7-72.9-64s32.7-64 72.9-64c38.2 0 73.4 36.1 94 64-20.4 27.6-55.9 64-94 64zm302.2 0c-38.2 0-73.4-36.1-94-64 20.4-27.6 55.9-64 94-64 40.2 0 72.9 28.7 72.9 64s-32.7 64-72.9 64z"/>';
											$unlimited .= '</svg>';
											$unlimited .= '</i>';
											$unlimited .= '<span class="screen-reader-text">' . esc_html__( 'Unlimited', 'storeengine-sdk' ) . '</span>';
											printf(
											/* translators: 1: Remaining activation, 2: Total activation (limit) */
													esc_html__( '%1$d out of %2$s', 'storeengine-sdk' ),
													esc_attr( $this->license['activations'] ),
													$unlimited
											);
											?>
										</p>
									<?php } else { ?>
										<p class="<?php echo $remaining ? 'active' : 'inactive'; ?>">
											<?php
											/* translators: 1: Remaining activation, 2: Total activation (limit) */
											printf( esc_html__( '%1$d out of %2$d', 'storeengine-sdk' ), esc_attr( $remaining ), esc_attr( $this->license['limit'] ) );
											?>
										</p>
									<?php } ?>
								<?php } else { ?>
									<p class="inactive"><?php esc_html_e( 'N/A', 'storeengine-sdk' ); ?></p>
								<?php } ?>
							</div>
							<div class="single-license-info automatic-update">
								<h3><?php esc_html_e( 'Automatic Update: ', 'storeengine-sdk' ); ?></h3>
								<p class="<?php echo esc_attr( $status ); ?>"><?php 'active' === $status ? esc_html_e( 'Enabled', 'storeengine-sdk' ) : esc_html_e( 'Disabled', 'storeengine-sdk' ); ?></p>
							</div>
						</div>
					<?php } ?>
				</div>
			</div>
		</div>
	</div>
<?php
