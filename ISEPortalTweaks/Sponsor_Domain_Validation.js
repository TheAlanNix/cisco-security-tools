/*
 * Sponsor_Domain_Validation.js 
 * 
 * Author: Alan Nix
 * Version: 1.0
 * Release Date: 08/29/2018
 * 
 * The Javascript below is meant to validate the email address domain that the Guest enters in the "Person Being Visited" field.
 * The script will check against the "allowed_domains" variable, and de-activate the registration form if the domain is not valid.
 * The user will also receive visual feedback that the domain is invalid.
 *
 * NOTE:  This is ONLY client-side validation, and does not prevent the user from modifying the Javascript in their local browser... but it's better than nothing.
 *
 * Place this code in the "Registration Form" -> "Optional Content 1" portion of the Self-Registered Portal's page customizations.
 */

<script>

	var allowed_domains = ['example.com'];

	$(function() {
		
		var timeout;

		$('#guestUser\\.fieldValues\\.ui_person_visited').on('input focus focusout', function () {
			clearTimeout(timeout);
			timeout = setTimeout(validateEmail, 300);
		});
	});

	function validateEmail() {

		var entered_email = $('#guestUser\\.fieldValues\\.ui_person_visited').val();

		var split_email = entered_email.split("@");

		if (split_email.length > 1) {
			if (split_email[1].length > 1) {

				for (i = 0; i < allowed_domains.length; i++) {
					console.log("Comparing " + allowed_domains[i] + " to " + split_email[1]);
					console.log(allowed_domains[i] == split_email[1]);

					if (allowed_domains[i] == split_email[1]) {
						$('#guestUser\\.fieldValues\\.ui_person_visited').removeClass('ui-body-c');
						$('#guestUser\\.fieldValues\\.ui_person_visited').parent().removeClass('ui-body-c');
						$('#ui_invalid_domain').remove();
						$('#ui_self_reg_submit_button').removeAttr("disabled");
						return;
					}
				}

				console.log("Domain " + split_email[1] + " was invalid.");

				$('#guestUser\\.fieldValues\\.ui_person_visited').addClass('ui-body-c');
				$('#guestUser\\.fieldValues\\.ui_person_visited').parent().addClass('ui-body-c');
				if ($('#ui_invalid_domain').length == 0) {
					$('#guestUser\\.fieldValues\\.ui_person_visited').parent().before('<label id="ui_invalid_domain" for="guestUser.fieldValues.ui_person_visited" class="error ui-body-c" style="display: inline;">Invalid email domain.</label>');
				} else {
					$('#ui_invalid_domain').show();
				}
				$('#ui_self_reg_submit_button').attr("disabled", "disabled");
			}
		}
	}
</script>