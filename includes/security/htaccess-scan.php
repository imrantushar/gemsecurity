<?php
namespace GemSecurity\Security;

use GemSecurity\Helper;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * .htaccess inspection.
 *
 * An .htaccess file is the quietest place to hide a compromise: it runs before
 * any PHP the scanner reads, it is not covered by core checksums, and it never
 * looks like code. The two that matter most are `auto_prepend_file`, which
 * loads a back-door into every request on the site, and re-enabling PHP
 * execution inside uploads, which turns an image upload into a shell.
 *
 * Nearly every .htaccess on a real install is a plugin locking its own folder
 * down — "Deny from all", "Require all denied". Those are the opposite of a
 * problem and must never be reported, or the check is noise and gets ignored.
 * Only directives that *grant* something are flagged.
 *
 * Signature literals are hex-encoded via {@see Helper::sig()} for the same
 * reason the malware patterns are: a plugin archive containing the plain
 * strings trips third-party antivirus on the zip itself.
 */
class HtaccessScan {

	/** Files bigger than this are not hand-written rules. */
	const MAX_BYTES = 262144; // 256 KB.

	/** Most .htaccess files to collect before stopping. */
	const MAX_FILES = 500;

	/**
	 * Most directory entries to look at while collecting them.
	 *
	 * The match cap alone is not a bound: on a site with two dozen plugins the
	 * walk still visited every file in every one of them looking for a name it
	 * mostly did not find, which cost more than the rest of the scan combined.
	 */
	const MAX_VISITS = 40000;

	/**
	 * Every .htaccess worth looking at.
	 *
	 * @return string[] Absolute paths.
	 */
	private static function targets() {
		$found = [];

		foreach ( [ ABSPATH, ABSPATH . 'wp-admin/', ABSPATH . 'wp-includes/', WP_CONTENT_DIR . '/' ] as $dir ) {
			$file = $dir . '.htaccess';
			if ( is_file( $file ) ) {
				$found[] = wp_normalize_path( $file );
			}
		}

		// Uploads gets the deep walk: this is where planted rules actually turn
		// up, several folders down beside the payload. Plugins and themes get
		// one level, because a rule that matters sits at the root of the folder
		// it is trying to open up — and walking every file of every plugin to
		// find a filename that is usually absent is not worth the seconds.
		$up      = wp_get_upload_dir();
		$visits  = 0;
		$matches = 0;

		$collect = function ( $root, $depth ) use ( &$found, &$visits, &$matches ) {
			if ( ! is_dir( $root ) ) {
				return;
			}
			try {
				$it = new \RecursiveIteratorIterator(
					new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ),
					\RecursiveIteratorIterator::LEAVES_ONLY
				);
				$it->setMaxDepth( $depth );
			} catch ( \Exception $e ) {
				return;
			}
			foreach ( $it as $file ) {
				if ( $matches >= self::MAX_FILES || ++$visits > self::MAX_VISITS ) {
					return;
				}
				if ( '.htaccess' !== $file->getFilename() || ! $file->isFile() ) {
					continue;
				}
				$matches++;
				$found[] = wp_normalize_path( $file->getPathname() );
			}
		};

		$collect( $up['basedir'], -1 ); // Unlimited depth.
		$collect( WP_PLUGIN_DIR, 1 );   // plugin-slug/.htaccess
		$collect( get_theme_root(), 1 ); // theme-slug/.htaccess

		return array_values( array_unique( $found ) );
	}

	/**
	 * Directives that grant execution or redirect traffic, and what they mean.
	 *
	 * @return array<int,array{re:string,label:string,sev:string}>
	 */
	private static function rules() {
		$c = 'critical';
		$w = 'warning';

		return [
			// auto_prepend_file / auto_append_file — loads a file into every request.
			[
				're'    => Helper::sig( '2f5c626175746f5f2870726570656e647c617070656e64295f66696c655c622f69' ),
				'label' => __( 'Loads a PHP file into every request (auto_prepend_file / auto_append_file) — the classic persistent back-door.', 'gemsecurity' ),
				'sev'   => $c,
			],
			// Mapping any handler/type back to PHP.
			[
				're'    => Helper::sig( '2f5c6228416464547970657c41646448616e646c65727c53657448616e646c6572295b5e5c6e5d2a3f28782d68747470642d7068707c7068702d7363726970747c6170706c69636174696f6e5c2f782d68747470642d706870292f69' ),
				'label' => __( 'Re-enables PHP execution for files in this directory — an uploaded image can then be run as code.', 'gemsecurity' ),
				'sev'   => $c,
			],
			// Options +ExecCGI / +Includes.
			[
				're'    => Helper::sig( '2f5c624f7074696f6e735b5e5c6e5d2a5c2b28457865634347497c496e636c75646573295c622f69' ),
				'label' => __( 'Turns on CGI or server-side-include execution for this directory.', 'gemsecurity' ),
				'sev'   => $c,
			],
			// php_value / php_flag switching dangerous ini on.
			[
				're'    => Helper::sig( '2f5c627068705b35375d3f5f2876616c75657c666c6167295c732b28616c6c6f775f75726c5f28666f70656e7c696e636c756465297c736166655f6d6f64657c64697361626c655f66756e6374696f6e73292f69' ),
				'label' => __( 'Changes PHP security settings from inside the site directory (allow_url_include, disable_functions and similar).', 'gemsecurity' ),
				'sev'   => $c,
			],
			// Cloaking: rewrite on referer/user-agent out to another host.
			[
				're'    => Helper::sig( '2f5c6252657772697465436f6e645c732b255c7b485454505f28524546455245527c555345525f4147454e54295c7d5b5c735c535d7b302c3430307d3f5c625265777269746552756c655c732b5b5e5c6e5d2a3f68747470733f3a2f69' ),
				'label' => __( 'Redirects visitors to another site based on their referrer or browser — the signature of SEO-spam cloaking.', 'gemsecurity' ),
				'sev'   => $c,
			],
			// ErrorDocument pointing off-site.
			[
				're'    => Helper::sig( '2f5c624572726f72446f63756d656e745c732b5c642b5c732b68747470733f3a2f69' ),
				'label' => __( 'Sends error pages to an external URL.', 'gemsecurity' ),
				'sev'   => $w,
			],
		];
	}

	/**
	 * Run the inspection.
	 *
	 * @return array<int,array{file:string,reason:string,severity:string,removable:bool}>
	 */
	public static function run() {
		$findings = [];
		$root     = wp_normalize_path( untrailingslashit( ABSPATH ) );

		foreach ( self::targets() as $abs ) {
			// Never report our own lockdown files.
			if ( false !== strpos( $abs, '/gemsecurity' ) ) {
				continue;
			}
			if ( ! is_readable( $abs ) || filesize( $abs ) > self::MAX_BYTES ) {
				continue;
			}
			$body = @file_get_contents( $abs ); // phpcs:ignore
			if ( false === $body || '' === trim( $body ) ) {
				continue;
			}

			$hits = [];
			$sev  = 'warning';
			foreach ( self::rules() as $rule ) {
				if ( @preg_match( $rule['re'], $body ) ) { // phpcs:ignore
					$hits[] = $rule['label'];
					if ( 'critical' === $rule['sev'] ) {
						$sev = 'critical';
					}
				}
			}
			if ( ! $hits ) {
				continue;
			}

			$rel = str_replace( $root . '/', '', $abs );

			// The site's own root .htaccess holds WordPress's permalink rules.
			// Moving it away would break every pretty URL, and an attacker
			// normally *appends* to it rather than replacing it — so the
			// legitimate half would go too. Report it for hand-editing.
			$is_root = ( $abs === $root . '/.htaccess' );

			$findings[] = [
				'file'      => $rel,
				'reason'    => implode( ' ', $hits ),
				'severity'  => $sev,
				'removable' => ! $is_root,
				'note'      => $is_root
					? __( 'This is the site’s main .htaccess and carries the WordPress permalink rules. Remove only the offending lines by hand — moving the whole file would break every URL.', 'gemsecurity' )
					: '',
			];
		}

		return $findings;
	}
}
