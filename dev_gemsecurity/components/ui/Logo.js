import React from 'react';

/**
 * GemSecurity mark (Figma "Brand" shield). Inline so it follows `color`
 * via currentColor and never depends on an external asset.
 */
export default function Logo( { size = 20, className = '' } ) {
	return (
		<svg
			className={ `gs-logo ${ className }` }
			width={ size }
			height={ size }
			viewBox="0 0 20 20"
			fill="none"
			aria-hidden="true"
			focusable="false"
		>
			<path
				fill="currentColor"
				d="M10.3592 0.425073L17.6317 2.24343C17.8744 2.30412 18.0447 2.52252 18.0447 2.77273V9.13601C18.0447 14.4273 14.656 17.7649 10.4481 19.635C10.3071 19.6975 10.1456 19.6976 10.0047 19.635C5.79709 17.7648 2.40803 14.427 2.40803 9.13601V2.77273C2.40812 2.52264 2.57951 2.30423 2.82209 2.24343L10.0945 0.425073L10.16 0.413354C10.2262 0.405197 10.2941 0.408861 10.3592 0.425073ZM3.49982 9.13601C3.49982 13.5358 6.09865 16.4644 9.68146 18.2708V9.13601H3.49982ZM10.7733 9.13601H16.9539V3.19851L10.7733 1.65164V9.13601Z"
			/>
		</svg>
	);
}
