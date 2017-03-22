<?php

$ip_address = $_REQUEST['ip_address'];

$looker_upper = new AMPLookup;
$looker_upper->getGUIDbyIP($ip_address);

class AMPLookup
{
    // Change these to have the customer's AMP API info
    private $AMP_CLIENT_ID  = "";
    private $AMP_API_KEY    = "";
    private $AMP_HOST       = "";

    public function getGUIDbyIP($ip_address)
    {
        // Build a URL to fetch info for the computer at the given IP
        $computers_url = "https://" . $this->AMP_CLIENT_ID . ":" . $this->AMP_API_KEY . "@" . $this->AMP_HOST . "/v1/computers?internal_ip=" . $ip_address;

        // Fetch the computer's data and parse the JSON
        $computers_data = $this->curlGetRequest($computers_url);
        $computers_data = json_decode($computers_data);

        if (count($computers_data->data) > 0) {
            header('Location: https://console.amp.cisco.com/computers/' . $computers_data->data[0]->connector_guid . '/trajectory');
        } else {
            echo "You had no Computers with the provided IP.";
            print_r($computers_data);
            exit;
        }
    }

    /**
     * Generic GET cURL method
     *
     * @param  Request URL      $url
     * @param  Request Headers  $headers
     * @return HTTP Response
     */
    private function curlGetRequest($url, $header = array())
    {
        try {
            // Fetch the data using cURL
            $curl = curl_init();
            curl_setopt_array($curl, array(
                CURLOPT_HTTPHEADER => $header,
                CURLOPT_RETURNTRANSFER => 1,
                CURLOPT_SSL_VERIFYHOST => 1,
                CURLOPT_SSL_VERIFYPEER => 1,
                CURLOPT_TIMEOUT => 10,
                CURLOPT_URL => $url,
            ));
            $response = curl_exec($curl);
            $curlinfo = curl_getinfo($curl);
            curl_close($curl);

            // Make sure we got an HTTP/200 or else error out.
            if ($curlinfo['http_code'] >= 200 && $curlinfo['http_code'] < 300) {

                // Return the Response
                return $response;

            } else {
                print('cURL Connection Failure. Status code: ' . $curlinfo['http_code'] . ' URL: ' . $url);
            }
        } catch (exception $e) {
            // If we error out then print the message
            print('cURL Error: ' . $e->getMessage());
        }
    }
}