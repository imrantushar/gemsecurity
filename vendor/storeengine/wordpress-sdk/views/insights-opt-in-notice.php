<?php
/**
 * @var SE_License_SDK_Insights $this
 * @var array $what_tracked
 * @var string $terms_policy_text
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
	<div class="se-sdk-product-<?php echo esc_attr( $this->client->getSlug() ); ?> se-sdk-insights-notice updated" style="--se-sdk-primary-color: <?php echo esc_attr( $this->client->getPrimaryColor() ); ?>;">
		<?php if ( $this->client->getProductLogo() ) { ?>
			<div class="se-sdk-insights-notice-branding">
				<img width="100" height="100" src="<?php echo esc_attr( $this->client->getProductLogo() ); ?>" alt="<?php echo esc_attr( $this->client->getPackageName() ); ?>">
			</div>
		<?php } ?>
		<div class="se-sdk-insights-notice-data">
			<div class="se-sdk-insights-notice--message">
				<?php echo wp_kses_post( $this->notice ); ?>
			</div>
			<?php if ( $what_tracked ) { ?>
			<details>
				<summary><?php esc_html_e( 'What we collect?', 'storeengine-sdk' ); ?></summary>
				<div class="description">
					<ul>
						<?php foreach ( $what_tracked as $key => $item ) { ?>
							<li class="trac-<?php echo esc_attr( $key ); ?>">✅ <?php echo esc_html( $item ); ?></li>
						<?php } ?>
					</ul>
				</div>
			</details>
			<?php } ?>
			<div class="se-sdk-insights--opt-in-submit">
                <?php if ( $terms_policy_text ) { ?>
					<p class="se-sdk-insights-notice--des"><?php echo wp_kses_post( $terms_policy_text ); ?></p>
				<?php } ?>
				<div class="buttons">
					<a href="<?php echo esc_url( $this->get_opt_in_url() ); ?>" class="button button-primary"><?php esc_html_e( 'Yes, keep me updated', 'storeengine-sdk' ); ?></a>
					<a href="<?php echo esc_url( $this->get_opt_out_url() ); ?>" class="button button-secondary"><?php esc_html_e( 'No thanks', 'storeengine-sdk' ); ?></a>
				</div>
			</div>
		</div>
	</div>
	<style>
        .se-sdk-insights-notice {
            display: flex;
            flex-direction: row;
            gap: 24px;
            color: #1E1E1E;
            padding: 24px 32px !important;
            border-width: 0 !important;
            border-left-color: var( --se-sdk-primary-color ) !important;
            border-left-width: 4px !important;
        }

        @media (max-width: 768px) {
            .se-sdk-insights-notice {
                display: flex;
                flex-direction: column;
                gap: 0;
                padding: 12px 16px !important;
            }

            .se-sdk-insights--opt-in-submit {
                display: flex;
                flex-direction: column;
            }

            .se-sdk-insights-notice-branding {
                display: flex;
                justify-content: center;
            }
        }

        .se-sdk-insights-notice details summary,
        .se-sdk-insights-notice a,
        .se-sdk-insights-notice .highlight {
            background-color: transparent;
            color: var( --se-sdk-primary-color );
        }

        .se-sdk-insights-notice details {
            margin-bottom: 16px;
		}
        .se-sdk-insights-notice details summary {
			cursor: pointer;
			text-decoration: underline;
            font-size: 14px;
		}

        .se-sdk-insights-notice a:focus {
            box-shadow: 0 0 0 2px var( --se-sdk-primary-color );
        }

        .se-sdk-insights-notice--title {
            color: #1E1E1E;
            font-size: 20px;
            font-style: normal;
            font-weight: 600;
            line-height: 30px;
            margin: 0 0 8px;
        }

        .se-sdk-insights-notice.updated p {
            margin: 0;
            padding: 0;
        }

        .se-sdk-insights-notice--des {
            color: #595959;
            font-size: 14px;
            font-style: normal;
            font-weight: 400;
            line-height: 20px;
            margin-bottom: 16px;
        }

        .se-sdk-insights-notice .description {
            margin-bottom: 16px;
            color: #0F0E16;
            font-size: 14px;
            font-style: normal;
            font-weight: 500;
            line-height: 20px;
        }

        .se-sdk-insights-notice .description ul {
			list-style: none;
		}
        .se-sdk-insights-notice .description li {
            margin-bottom: 8px;
        }

        .se-sdk-insights-notice--message {
            margin-bottom: 16px;
        }

        .se-sdk-insights--opt-in-submit {
            display: flex;
            flex-direction: column;
            gap: 16px;
            margin: 0;
            padding: 0
        }

        .se-sdk-insights--opt-in-submit .buttons {
            margin-right: auto;
            display: flex;
            gap: 12px
        }

        .se-sdk-insights--opt-in-submit .buttons a.button-primary {
            border-radius: 4px;
            padding: 6px 12px;
            color: #FFFFFF;
            background: var( --se-sdk-primary-color );
            text-align: center;
            font-size: 14px;
            font-style: normal;
            font-weight: 500;
            line-height: 20px;
            border: none;
            height: auto !important;
        }
        .se-sdk-insights--opt-in-submit .buttons a.button-primary:focus {
            box-shadow: 0 0 0 1px #fff, 0 0 0 3px var( --se-sdk-primary-color );
        }

        .se-sdk-insights--opt-in-submit .buttons a.button-secondary {
            border: 1px solid #DEDEDE;
            border-radius: 4px;
            padding: 6px 12px;
            text-align: center;
            font-size: 14px;
            font-style: normal;
            font-weight: 500;
            line-height: 20px;
            color: #0F0E16;
            background: #FFFFFF;
            height: auto !important;
        }
        .se-sdk-insights--opt-in-submit .buttons a.button-secondary:focus {
            box-shadow: 0 0 0 1px #fff, 0 0 0 2px #DEDEDE;
        }
	</style>
<?php
