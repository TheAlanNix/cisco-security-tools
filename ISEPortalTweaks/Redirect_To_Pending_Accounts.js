/*
 * Redirect_To_Pending_Accounts.js 
 * 
 * Author: Alan Nix
 * Version: 1.0
 * Release Date: 08/29/2018
 * 
 * The Javascript below is meant to redirect users to the "Pending Accounts" tab in the ISE Sponsor Portal.
 * This is done to ease the workflow of approving a pending guest account.
 *
 * Place this code in the "Sposor Portal Settings" -> "Instructional Text" portion of the Sponsor Portal's page customizations.
 */

<script>
	$(function() {
		current_url = window.location.href;
		current_url = current_url.split('#');
		current_url = current_url[0];

		window.location.href = current_url + "#approveAccountsList";
	});
</script>