<?php
namespace GemBackup\Engine;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Resumable ZIP archiver.
 * State shape:
 * {
 *   sources:   [ 'wp-content/themes', 'wp-content/plugins', ... ]   // top-level roots
 *   file_list: '/path/to/temp/file_list.txt'                        // newline-delimited absolute paths
 *   index:     0,                                                   // line index in file_list
 *   total:     N,                                                   // total files
 *   completed: false,
 * }
 */
class File_Archiver {

	const FILES_PER_TICK = 250;
	const MAX_FILE_SIZE  = 2147483648; // 2 GB hard cap per file to skip enormous files

	public static function init_state( $backup_type ) {
		$abspath = trailingslashit( ABSPATH );
		$content = trailingslashit( WP_CONTENT_DIR );
		$upload  = wp_upload_dir();
		$upload_basedir = trailingslashit( $upload['basedir'] );

		$sources = [];
		switch ( $backup_type ) {
			case 'media':
				$sources = [ $upload_basedir ];
				break;
			case 'files':
				$sources = [ $content ];
				break;
			case 'full':
			default:
				$sources = [ $abspath ];
				break;
		}

		// Build the file list.
		$list_path = GEMBACKUP_BACKUP_DIR_PATH . 'tmp-filelist-' . wp_generate_uuid4() . '.txt';
		$lp = fopen( $list_path, 'wb' );
		if ( ! $lp ) {
			return new \WP_Error( 'gembackup_archive_init', 'Cannot create file list' );
		}

		$excludes = self::get_excludes();
		$total = 0;
		foreach ( $sources as $root ) {
			$total += self::walk( $root, $excludes, $lp );
		}
		fclose( $lp );

		return [
			'sources'   => $sources,
			'file_list' => $list_path,
			'index'     => 0,
			'total'     => $total,
			'completed' => $total === 0,
		];
	}

	private static function get_excludes() {
		$settings = get_option( GEMBACKUP_SETTINGS_NAME, [] );
		$lines = array_filter( array_map( 'trim', explode( "\n", $settings['exclude_paths'] ?? '' ) ) );
		// Never include our own backup directory. Fixed stale name: this was
		// "wp-content/gembackup" from before the engine was re-homed into
		// GemSecurity as "gemsecurity-backups" (GemSecurity\Backup::BACKUP_DIR),
		// so a full backup was silently bundling every previous backup archive
		// into itself.
		$lines[] = 'wp-content/gemsecurity-backups';
		$lines[] = 'wp-content/cache';
		$lines[] = '.git';
		$lines[] = 'node_modules';
		// Never bundle wp-config.php: a "full" backup has no business shipping
		// DB credentials and secret keys inside itself.
		$lines[] = 'wp-config.php';
		return $lines;
	}

	private static function walk( $root, $excludes, $lp ) {
		$count = 0;
		try {
			$it = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ),
				\RecursiveIteratorIterator::SELF_FIRST
			);
		} catch ( \Exception $e ) {
			return 0;
		}

		foreach ( $it as $file ) {
			if ( $file->isDir() ) continue;
			$path = $file->getPathname();
			if ( self::is_excluded( $path, $excludes ) ) continue;
			if ( $file->getSize() > self::MAX_FILE_SIZE ) continue;
			fwrite( $lp, $path . "\n" );
			$count++;
		}
		return $count;
	}

	private static function is_excluded( $path, $excludes ) {
		$rel = str_replace( '\\', '/', $path );
		foreach ( $excludes as $pattern ) {
			if ( $pattern === '' ) continue;
			if ( strpos( $rel, $pattern ) !== false ) return true;
		}
		return false;
	}

	public static function tick( $zip_path, array $state ) {
		if ( ! empty( $state['completed'] ) ) {
			return $state;
		}
		if ( ! class_exists( 'ZipArchive' ) ) {
			return new \WP_Error( 'gembackup_no_zip', __( 'PHP ZipArchive extension is required.', 'gembackup' ) );
		}

		$zip = new \ZipArchive();
		$open = $zip->open( $zip_path, file_exists( $zip_path ) ? \ZipArchive::CREATE : \ZipArchive::CREATE | \ZipArchive::OVERWRITE );
		if ( $open !== true ) {
			return new \WP_Error( 'gembackup_zip_open', 'Unable to open zip archive' );
		}

		$fp = fopen( $state['file_list'], 'rb' );
		if ( ! $fp ) {
			$zip->close();
			return $state;
		}

		// Skip to current index
		$i = 0;
		while ( $i < $state['index'] && ! feof( $fp ) ) {
			fgets( $fp );
			$i++;
		}

		$processed = 0;
		$abspath = trailingslashit( ABSPATH );

		while ( $processed < self::FILES_PER_TICK && ! feof( $fp ) ) {
			$line = trim( fgets( $fp ) );
			if ( $line === '' ) {
				$state['index']++;
				continue;
			}
			$relative = ltrim( str_replace( $abspath, '', $line ), '/\\' );
			$zip->addFile( $line, $relative );
			$state['index']++;
			$processed++;
		}

		fclose( $fp );
		$zip->close();

		if ( $state['index'] >= $state['total'] ) {
			$state['completed'] = true;
			@unlink( $state['file_list'] );
		}

		return $state;
	}

	public static function progress( $state ) {
		$total = max( 1, $state['total'] );
		return min( 100, (int) ( ( $state['index'] / $total ) * 100 ) );
	}

	public static function add_sql_to_zip( $zip_path, $sql_path, $manifest_path ) {
		$zip = new \ZipArchive();
		if ( $zip->open( $zip_path ) !== true ) {
			return new \WP_Error( 'gembackup_zip_open', 'Unable to open zip for SQL injection' );
		}
		if ( file_exists( $sql_path ) ) {
			$zip->addFile( $sql_path, 'gembackup-database.sql' );
		}
		if ( $manifest_path && file_exists( $manifest_path ) ) {
			$zip->addFile( $manifest_path, 'manifest.json' );
		}
		$zip->close();
		return true;
	}

	public static function extract( $zip_path, $destination ) {
		if ( ! class_exists( 'ZipArchive' ) ) {
			return new \WP_Error( 'gembackup_no_zip', 'PHP ZipArchive extension is required.' );
		}
		$zip = new \ZipArchive();
		if ( $zip->open( $zip_path ) !== true ) {
			return new \WP_Error( 'gembackup_zip_open', 'Cannot open backup zip' );
		}

		// Zip-slip guard: modern PHP/libzip have their own protections
		// against path-traversal entries, but a restore copies this straight
		// over live wp-content (Restore_Runner::phase_files()), so this
		// doesn't rely on exactly what a given host's PHP/libzip build does.
		// All-or-nothing — a single unsafe entry aborts the whole
		// extraction rather than silently extracting a "safe" subset, which
		// could leave a restore in a subtly broken, hard-to-notice state.
		$unsafe = self::find_unsafe_entry( $zip );
		if ( null !== $unsafe ) {
			$zip->close();
			return new \WP_Error(
				'gembackup_zip_unsafe',
				sprintf( 'Backup archive contains an unsafe file path (%s) and was not extracted.', $unsafe )
			);
		}

		wp_mkdir_p( $destination );
		$ok = $zip->extractTo( $destination );
		$zip->close();
		return $ok ? true : new \WP_Error( 'gembackup_zip_extract', 'Failed to extract' );
	}

	/**
	 * Scan every entry in an open zip for a path that would escape the
	 * intended extraction directory.
	 *
	 * @param \ZipArchive $zip
	 * @return string|null The first unsafe entry name found, or null if the
	 *                      whole archive is safe.
	 */
	private static function find_unsafe_entry( \ZipArchive $zip ) {
		for ( $i = 0; $i < $zip->numFiles; $i++ ) {
			$name = $zip->getNameIndex( $i );
			if ( false === $name || '' === $name ) {
				continue;
			}
			if ( self::is_unsafe_zip_entry_name( $name ) ) {
				return $name;
			}
		}
		return null;
	}

	/**
	 * @param string $name Raw entry name as stored in the zip.
	 * @return bool
	 */
	private static function is_unsafe_zip_entry_name( $name ) {
		if ( false !== strpos( $name, "\0" ) ) {
			return true;
		}
		// Absolute paths (POSIX or Windows-drive). Zip entries are always
		// forward-slash per spec, so any backslash is either an unusual
		// literal filename character or a smuggled Windows separator —
		// either way, not worth trying to guess which.
		if ( '/' === $name[0] || '\\' === $name[0] || preg_match( '#^[a-zA-Z]:#', $name ) ) {
			return true;
		}
		if ( false !== strpos( $name, '\\' ) ) {
			return true;
		}
		// ".." as a whole path segment, not merely a substring — so a real
		// filename like "file..name.txt" is unaffected, but "../x" or
		// "a/../../x" is rejected.
		foreach ( explode( '/', $name ) as $segment ) {
			if ( '..' === $segment ) {
				return true;
			}
		}
		return false;
	}
}
