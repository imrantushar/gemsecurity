<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
	<head>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />
		<title><?php echo esc_html__( 'GemSecurity Setup', 'gemsecurity' ); ?></title>
		<?php do_action( 'admin_print_styles' ); ?>
		<?php do_action( 'admin_print_scripts' ); ?>
	</head>
	<body class="gemsecurity-setup-body">
		<div id="gemsecuritywrap" class="gemsecuritywrap gs-setup"></div>
		<?php do_action( 'admin_print_footer_scripts' ); ?>
	</body>
</html>
