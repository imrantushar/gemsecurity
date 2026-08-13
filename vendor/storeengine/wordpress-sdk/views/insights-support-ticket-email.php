<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// dynamic variable format __INPUT_NAME__

?>
	<div style="margin:10px auto">
		<p style="margin:5px 0;"><strong>Website:</strong> <a href="__WEBSITE__" style="color:#008DFF;text-decoration:none" target="_blank">__WEBSITE__</a></p>
		<p style="margin:5px 0;"><strong>Plugin:</strong> <span><?php echo $this->client->getPackageName() . ' (v.' . $this->client->getProjectVersion() . ')'; ?></span></p>
		<p style="margin:5px 0;"><strong>Name:</strong> <span>__NAME__</span></p>
		<p style="margin:5px 0;"><strong>Email:</strong> <span><a href="mailto:__EMAIL__" style="color:#008DFF;text-decoration:none">__EMAIL__</a></span></p>
		<p style="margin:5px 0;"><strong>Subject:</strong> <span>__SUBJECT__</span></p>
	</div>
	<div style="margin:10px auto">
		<h3 style="margin:5px 0;">Message:</h3>
		<div style="margin-left:40px;padding-left:15px;border-left:4px solid #008DFF">__MESSAGE__</div>
	</div>
<?php
