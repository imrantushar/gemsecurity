(function($, window) {
	'use strict';

	if (window.StoreEngineSDKDeactivationModal) {
		$(window.StoreEngineSDKDeactivationModal.init);
		return;
	}

	function preventDefault(event) {
		if (event) {
			event.preventDefault();
		}
	}

	/**
	 * Put a button into a disabled+spinner state. Returns the original
	 * label so the caller can restore it if the action is reversible.
	 */
	function setButtonLoading(buttonElem, config) {
		if (buttonElem.data('se-sdk-original-label') == null) {
			buttonElem.data('se-sdk-original-label', buttonElem.text());
		}
		var label = config.processingLabel || 'Processing...';
		// `loading` keeps the button's primary colour; `disabled` blocks
		// further clicks. The CSS targets the combination so the spinner
		// stays visible against the original background rather than
		// dropping to the muted disabled style.
		buttonElem.addClass('disabled loading').prop('disabled', true).html(
			'<span class="se-sdk-spinner" aria-hidden="true"></span>' +
			'<span class="se-sdk-spinner-label">' + label + '</span>'
		);
	}

	function restoreButton(buttonElem) {
		var label = buttonElem.data('se-sdk-original-label');
		if (label != null) {
			buttonElem.removeClass('disabled loading').prop('disabled', false).text(label);
		}
	}

	function ajaxSubmit(data, buttonElem, callback, config) {
		if (buttonElem.hasClass('disabled') || buttonElem.is(':disabled')) {
			return;
		}

		return $.ajax({
			url: window.ajaxurl,
			type: 'POST',
			data: $.extend({}, {
				action: config.uninstallAction,
				_wpnonce: config.nonce
			}, data),
			beforeSend: function() {
				setButtonLoading(buttonElem, config);
			},
			complete: function(event, xhr, options) {
				restoreButton(buttonElem);
				if (typeof callback === 'string') {
					window.location.href = callback;
				} else if (typeof callback === 'function') {
					callback({ event: event, xhr: xhr, options: options });
				}
			}
		});
	}

	/**
	 * Fire-and-forget feedback delivery via sendBeacon. Used when the user
	 * provides a real reason — we don't need to wait for the server's
	 * acknowledgement before navigating to the WP deactivate URL, because
	 * the browser delivers beacon payloads even after page unload.
	 *
	 * Returns true if the beacon was queued; false if not supported (caller
	 * should fall back to ajaxSubmit).
	 */
	function sendFeedbackBeacon(data, config) {
		if (!window.navigator || typeof window.navigator.sendBeacon !== 'function') {
			return false;
		}

		var payload = $.extend({}, {
			action: config.uninstallAction,
			_wpnonce: config.nonce
		}, data);

		try {
			var body = new URLSearchParams();
			Object.keys(payload).forEach(function (key) {
				body.append(key, payload[key] == null ? '' : payload[key]);
			});
			// admin-ajax expects application/x-www-form-urlencoded; Blob lets
			// us set the MIME type explicitly because sendBeacon defaults to
			// text/plain for raw strings, which WP rejects.
			return window.navigator.sendBeacon(
				window.ajaxurl,
				new Blob([body.toString()], { type: 'application/x-www-form-urlencoded' })
			);
		} catch (err) {
			return false;
		}
	}

	function initModal(modal) {
		if (!modal.length || modal.data('seSdkModalInit')) {
			return;
		}

		modal.data('seSdkModalInit', true);

		var config = {
			slug: modal.data('slug'),
			plugin: modal.data('plugin'),
			uninstallAction: modal.data('uninstall-action'),
			supportAction: modal.data('support-action'),
			nonce: modal.data('nonce'),
			supportUrl: modal.data('support-url'),
			processingLabel: modal.data('processing-label') || 'Processing...'
		};

		var deactivateLink = '';
		var reason = modal.find('.reason');
		var support = modal.find('.support');
		var supportResponse = support.find('.response');
		var mui = modal.find('.mui input, .mui textarea, .mui select');
		var responseButtons = modal.find('.reason .se-sdk-deactivation-modal--footer .send-reason');
		var validMessage = [];

		function resetTicketForm(clearValues, clearAll) {
			modal.find('p.helper-text.mui-error').remove();
			modal.find('.mui-error').removeClass('mui-error');
			if (!clearValues) {
				return;
			}
			if (clearAll) {
				mui.val('');
				return;
			}
			modal.find('#' + config.slug + '-se-sdk-support--message,#' + config.slug + '-se-sdk-support--subject').val('');
		}

		function closeModal(event) {
			preventDefault(event);
			$('body').removeClass('se-sdk-deactivation-modal-open');
			modal.removeClass('modal-active');
			supportResponse.hide().find('.wrapper').html('');
			support.hide();
			reason.show(0);
			modal.find('.button').removeClass('disabled').prop('disabled', false).each(function() {
				var self = $(this);
				var label = self.attr('data-label');
				if (label) {
					self.text(label);
				}
			});
			modal.find('input[type="radio"]').prop('checked', false).removeClass('selected-reason');
			// Collapse the "What data do we collect?" disclosure so it starts
			// hidden again on the next open.
			modal.find('.se-sdk-consent-details').prop('open', false);
			modal.find('.reason-input').remove();
		}

		function checkMessageValidity(event) {
			var target = event && event.target ? event.target : this;
			var self = $(this);
			var currentMui = self.closest('.mui');
			var label = currentMui.find('label');
			var control = currentMui.find('.se-sdk-form-control');

			if (target.checkValidity()) {
				label.removeClass('mui-error');
				control.removeClass('mui-error');
				currentMui.find('p.helper-text').hide().remove();
				validMessage.push(true);
				return;
			}

			validMessage.push(false);
		}

		mui.not('select').not('[type="checkbox"]').not('[type="radio"]').on('focus', function() {
			var self = $(this);
			var currentMui = self.closest('.mui');
			currentMui.find('.se-sdk-form-control').addClass('focused');
			currentMui.find('label').addClass('focused shrink');
		}).on('blur', function() {
			var self = $(this);
			var currentMui = self.closest('.mui');
			var label = currentMui.find('label');
			currentMui.find('.se-sdk-form-control').removeClass('focused');
			label.removeClass('focused');
			if (self.val() === '') {
				label.removeClass('shrink');
			}
		});

		mui.on('blur', checkMessageValidity).on('invalid', function(event) {
			preventDefault(event);
			var self = $(this);
			var currentMui = self.closest('.mui');
			var label = currentMui.find('label');
			var control = currentMui.find('.se-sdk-form-control');
			currentMui.find('p.helper-text').remove();
			label.addClass('mui-error');
			control.addClass('mui-error');
			control.after('<p class="helper-text mui-error">' + event.target.validationMessage + '</p>');
		});

		// Bind to the plugin's "Deactivate" link. Prefer data-plugin (the
		// plugin file basename) because WordPress always sets it on the row and
		// it's unique — data-slug is derived from the wp.org slug / plugin name
		// and won't match when the SDK's configured slug differs (e.g. a "-pro"
		// product slug on a differently-named plugin folder), which would leave
		// the modal never opening. data-slug is kept as a fallback.
		var deactivateRow = config.plugin
			? $('tr[data-plugin="' + config.plugin + '"]')
			: $();
		if (!deactivateRow.length) {
			deactivateRow = $('tr[data-slug="' + config.slug + '"]');
		}
		deactivateRow.find('.deactivate a').off('click.seSdkModal').on('click.seSdkModal', function(event) {
			preventDefault(event);
			$('body').addClass('se-sdk-deactivation-modal-open');
			modal.addClass('modal-active');
			deactivateLink = $(this).attr('href');
			modal.find('a.dont-bother-me').attr('href', deactivateLink).css('float', 'left');
		});

		modal.on('click', '.not-interested', function(event) {
			preventDefault(event);
			$(this).closest('.response').slideUp();
			responseButtons.removeClass('disabled').prop('disabled', false);
		}).on('click', '.open-ticket-form', function(event) {
			preventDefault(event);
			support.show(0);
			reason.hide(0);
			supportResponse.find('.wrapper').html('');
			supportResponse.hide(0);
			resetTicketForm(true);
		}).on('click', '.close-ticket', function(event) {
			preventDefault(event);
			support.hide(0);
			reason.show(0);
		}).on('click', '.modal-close, .se-sdk-deactivation-modal--close', closeModal).on('click', '.reason-type', function() {
			var self = $(this);
			var parent = self.closest('.reason-item');
			var inputType = parent.data('type');
			modal.find('.reason-input').slideUp(function() {
				$(this).remove();
			});
			self.closest('.reasons').find('.selected-reason').removeClass('selected-reason');
			self.addClass('selected-reason');

			// For "found-better" / "other" expose an optional follow-up
			// input. It's not required — Submit & Deactivate stays enabled
			// whether or not the user fills it in.
			if (inputType !== '') {
				var reasonMessage = $(inputType === 'text' ? '<input type="text" size="40" />' : '<textarea rows="5" cols="45"></textarea>');
				reasonMessage.attr('placeholder', parent.data('placeholder'));
				reasonMessage.slideUp(0);
				$('<div class="reason-input"></div>').append(reasonMessage).appendTo(parent);
				reasonMessage.slideDown('fast').focus();
			}
		}).on('click', '.dont-bother-me', function(event) {
			preventDefault(event);
			// User explicitly chose not to share — nothing useful to record.
			// Show a brief spinner so the click feels acknowledged, then
			// deactivate immediately (no server round-trip).
			setButtonLoading($(this), config);
			window.location.href = deactivateLink;
		}).on('click', '.send-reason', function(event) {
			preventDefault(event);
			if ($(this).hasClass('disabled') || $(this).is(':disabled')) {
				return;
			}
			var radio = modal.find('input.reason-type:checked');
			var input = radio.length
				? radio.closest('.reason-item').find('textarea, input[type="text"]')
				: $();

			// The modal discloses exactly what is sent (reason plus the listed
			// site data), and "Skip & Deactivate" is the cancel path that sends
			// nothing — so submitting here is informed consent.
			var payload = {
				reason_id: radio.length ? radio.val() : 'no-comment',
				reason_info: input.length ? $.trim(input.val()) : ''
			};

			// Show spinner immediately so the click feels acknowledged,
			// independent of whether we use beacon or fall back to AJAX.
			setButtonLoading($(this), config);

			// Try sendBeacon first — browser delivers it even after we
			// navigate away, so the user doesn't wait for the server.
			if (sendFeedbackBeacon(payload, config)) {
				window.location.href = deactivateLink;
				return;
			}

			// Fallback: old-school AJAX with loader. Only hit on browsers
			// without sendBeacon support (≤ IE / very old Safari).
			ajaxSubmit(payload, $(this), deactivateLink, config);
		}).on('click', '.send-ticket', function(event) {
			preventDefault(event);
			validMessage = [];
			mui.each(checkMessageValidity);
			if (!validMessage.every(Boolean)) {
				return;
			}

			var buttonElem = $(this);
			var buttonText = buttonElem.text();
			var data = {
				action: config.supportAction
			};

			mui.each(function() {
				data[$(this).attr('name')] = $(this).val();
			});

			ajaxSubmit(data, buttonElem, function(jqXhr) {
				buttonElem.removeClass('disabled').prop('disabled', false).text(buttonText);
				if (jqXhr.xhr === 'error') {
					supportResponse.find('.wrapper').html('<p class="mui-error">Something went wrong. Please refresh or try again.</p>');
					supportResponse.show();
					return;
				}

				var response = jqXhr.event.responseJSON;
				if (response && Object.prototype.hasOwnProperty.call(response, 'data')) {
					var message = response.success ? '<p>' + response.data + '</p>' : '<p class="mui-error">' + response.data + '</p>';
					supportResponse.find('.wrapper').html(message);
					supportResponse.show();
					if (response.success) {
						modal.find('#' + config.slug + '-se-sdk-support--message,#' + config.slug + '-se-sdk-support--subject').val('');
					}
					return;
				}

				if (!config.supportUrl) {
					return;
				}

				window.setTimeout(function() {
					window.open(config.supportUrl, '_blank');
					if (buttonElem.hasClass('disabled')) {
						buttonElem.removeClass('disabled').prop('disabled', false);
					}
				}, 5000);
			}, config);
		});
	}

	function init() {
		$('.se-sdk-deactivation-modal').each(function() {
			initModal($(this));
		});
	}

	window.StoreEngineSDKDeactivationModal = {
		init: init
	};

	$(init);
})(jQuery, window);
