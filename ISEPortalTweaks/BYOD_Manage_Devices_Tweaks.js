/*
 * BYOD_Manage_Devices_Tweaks.js
 * 
 * Author: Alan Nix
 * Version: 1.0
 * Release Date: 07/23/2019
 * 
 * The Javascript below is meant to hide 'Pending' devices in the ISE My Devices Portal.
 * This is done to remove end user confusion around the status of their devices.
 *
 * Place this code in the "My Devices" -> "Optional Content 1" portion of the My Devices Portal's page customizations.
 */

<script>
    $(function() {
        $('.manage-devices-table').change(removePendingDevices)
    });

    function removePendingDevices() {

        // Hide the row all together
        // $("td[title|='Pending']").parent().hide()

        // Rename from 'Pending' to 'Enrolling'
        $("td[title|='Pending']").html("<div class='inner-col'>Enrolling</div>")
    }
</script>