<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// dynamic variable format __INPUT_NAME__

?>
	<div style="margin:10px auto">
		<p><strong>Website:</strong> <a href="__WEBSITE__" target="_blank">__WEBSITE__</a></p>
		<p><strong>Plugin:</strong> <span><?php echo $this->client->getPackageName() . ' (v.' . $this->client->getProjectVersion() . ')'; ?></span></p>
		<p><strong>Name:</strong> <span>__NAME__</span></p>
		<p><strong>Email:</strong> <span>__EMAIL__</span></p>
		<p><strong>Subject:</strong> <span>__SUBJECT__</span></p>
	</div>
	<div style="margin:10px auto">
		<h3>Message:</h3>
		<div>__MESSAGE__</div>
	</div>
<?php
