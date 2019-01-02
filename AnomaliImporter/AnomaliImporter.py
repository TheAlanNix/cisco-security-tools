#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# AnomaliImporter.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 0.2
# Release Date: 10/18/2016
#
# Summary
# -------
#
# This script imports IP data from Anomali (ThreatStream) into Host Groups within Stealthwatch
#
# Version 0.2: Updated to use Python 3, and converted from tabs to spaces (even though it caused me to die inside a little)
#
# Requirements
# ------------
#
#   1) Must have Python 3 installed.
#   2) Must have 'requests' Python module installed.  Easiest way to do that:
#     - wget https://bootstrap.pypa.io/get-pip.py
#     - python get-pip.py		(may need to use 'sudo')
#     - pip install requests	(may need to use 'sudo')
#
#
# How To Run
# ----------
#
#   1) Configure Anomali API_USER and API_KEY - can also tune the CONFIDENCE parameter
#   2) Configure StealthWatch SW_DOMAIN_ID, SW_SMC_IP, SW_USERNAME, SW_PASSWORD
#   3) Configure the HOST_GROUP_ID based on where you want groups to be imported
#   4) Run the script / set a cron job
#
############################################################


####################
#  CONFIGURATION   #
####################
#
#----------------------------------------------------#
#

# API Variables
API_USER  = 'example@example.com'
API_KEY   = '0000001111111222222333333344444'
API_BASE  = 'https://api.threatstream.com/api/v2'

# API result set limit
API_OFFSET = 1000

# Global Confidence Value
CONFIDENCE = 60

# StealthWatch SMC Variables
SW_DOMAIN_ID = "123"
SW_SMC_IP    = "127.0.0.1"
SW_USERNAME  = "admin"
SW_PASSWORD  = "lan411cope"

# StealthWatch Parent Host Group ID
HOST_GROUP_ID = 50000

ANOMALI_TYPES = {
    "Anonymous Proxies":    "anon_proxy",
    "Anonymous VPNs":       "anon_vpn",
    "APT Hosts":            "apt_ip",
    "Bot Hosts":            "bot_ip",
    "Brute Force Hosts":    "brute_ip",
    "Malware Hosts":        "mal_ip",
    "Scanning Hosts":       "scan_ip",
    "Spamming Hosts":       "spam_ip",
    "TOR Hosts":            "tor_ip"
}

#
#----------------------------------------------------#


####################
# !!! DO WORK !!!  #
####################

import requests
import xml.etree.ElementTree

from requests.auth import HTTPBasicAuth

# If receiving SSL Certificate Errors, un-comment the line below
#requests.packages.urllib3.disable_warnings()

#----------------------------------------------------#
# A function fetch data from Anomali
def queryAPI(itype):
    
    # Use global API variables
    global API_BASE, API_KEY, API_USER, API_OFFSET, CONFIDENCE

    print('Fetching {}, this may take a few minutes...'.format(itype))

    # An array variable to append IPs
    ip_array = []

    # Set iteration variables
    i = 0
    count = API_OFFSET

    while (count == API_OFFSET):
        # Adjust the fetch offset
        offset = i * API_OFFSET

        # Build the ThreatStream URL
        url = '{}/intelligence/?format=json&username={}&api_key={}&offset={}&status=active&itype={}&limit={}&confidence__gt={}'.format(API_BASE, API_USER, API_KEY, offset, itype, API_OFFSET, CONFIDENCE)

        # Print the full URL for the user
        print(url)

        # Try to communicate with Anomali
        try:
            
            # Make the GET request
            http_req = requests.get(url)
            
            # If we get a HTTP 200, then proceed
            if http_req.status_code == 200:
                
                # Make a counter
                count = len(http_req.json()['objects'])

                # Add all the IPs to our array
                for entry in http_req.json()['objects']:
                    
                    # Add the IP to our array
                    ip_array.append(entry['ip'])

            elif http_req.status_code == 401: 
                # Log an access denied
                print('Access Denied. Check API Credentials')
                exit()
            else:
                # Log a connection failure
                print('API Connection Failure. Status code: {}'.format(http_req.status_code))
                exit()
        except Exception as err:
            # Log any other type of error
            print('API Access Error: {}'.format(err))
            exit()

        # Increment the offset counter
        i += 1

    print('Returned {} {} IPs...'.format(len(ip_array), itype))

    # Return the array of IPs
    return ip_array
#----------------------------------------------------#

#----------------------------------------------------#
# A function to build getHostGroups XML for the SMC
def getHostGroupsXML():

    return_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    return_xml += "<soapenc:Envelope xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
    return_xml += "\t<soapenc:Body>\n"
    return_xml += "\t\t<getHostGroups>\n"
    return_xml += "\t\t\t<domain id=\"{}\" />\n".format(SW_DOMAIN_ID)
    return_xml += "\t\t</getHostGroups>\n"
    return_xml += "\t</soapenc:Body>\n"
    return_xml += "</soapenc:Envelope>"

    return return_xml
#----------------------------------------------------#

#----------------------------------------------------#
# A function to build addHostGroup XML for the SMC
def addHostGroupXML(ip_array, group_name):

    return_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    return_xml += "<soapenc:Envelope xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
    return_xml += "\t<soapenc:Body>\n"
    return_xml += "\t\t<addHostGroup>\n"
    return_xml += "\t\t\t<host-group domain-id=\"{}\" name=\"{}\" parent-id=\"{}\">\n".format(SW_DOMAIN_ID, group_name, HOST_GROUP_ID)

    for ip_address in ip_array:
        return_xml += "\t\t\t\t<ip-address-ranges>{}</ip-address-ranges>\n".format(ip_address)
    
    return_xml += "\t\t\t</host-group>\n"
    return_xml += "\t\t</addHostGroup>\n"
    return_xml += "\t</soapenc:Body>\n"
    return_xml += "</soapenc:Envelope>"

    return return_xml
#----------------------------------------------------#

#----------------------------------------------------#
# A function to build setHostGroupIPRange XML for the SMC
def setHostGroupIPRangeXML(ip_array, group_id):

    return_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    return_xml += "<soapenc:Envelope xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
    return_xml += "\t<soapenc:Body>\n"
    return_xml += "\t\t<setHostGroupIPRange>\n"
    return_xml += "\t\t\t<host-group id=\"{}\" domain-id=\"{}\">\n".format(group_id, SW_DOMAIN_ID)

    for ip_address in ip_array:
        return_xml += "\t\t\t\t<ip-address-ranges>{}</ip-address-ranges>\n".format(ip_address)

    return_xml += "\t\t\t</host-group>\n"
    return_xml += "\t\t</setHostGroupIPRange>\n"
    return_xml += "\t</soapenc:Body>\n"
    return_xml += "</soapenc:Envelope>"

    return return_xml
#----------------------------------------------------#

#----------------------------------------------------#
# A function to post supplied XML to the SMC
def submitXMLToSMC(xml):

    # Build the SMC URL
    SMC_URL = "https://{}/smc/swsService/configuration".format(SW_SMC_IP)

    # Build HTTP Authentication Instance
    auth = HTTPBasicAuth(SW_USERNAME, SW_PASSWORD)

    print("Posting data to the SMC...")

    # Try to make the POST, else print the error
    try:
        # Make the POST request
        http_req = requests.post(url=SMC_URL, auth=auth, data=xml, verify=False)

        # Check to make sure the POST was successful
        if http_req.status_code == 200:
            print('Success.')
            return http_req.text
        else:
            print('SMC Connection Failure - HTTP Return Code: {}\nResponse: {}'.format(http_req.status_code, http_req.json()))
            exit()

    except Exception as err:
        print('Unable to post to the SMC - Error: {}'.format(err))
        exit()
#----------------------------------------------------#

#----------------------------------------------------#
if __name__ == "__main__":

    # Get the Host Groups from StealthWatch
    host_groups_xml = submitXMLToSMC(getHostGroupsXML())

    # Parse the Host Group XML
    root = xml.etree.ElementTree.fromstring(host_groups_xml.encode('ascii', 'ignore'))

    # Get the Parent Host Group that was specified
    parent_host_group = root.find('.//{http://www.lancope.com/sws/sws-service}host-group[@id="' + str(HOST_GROUP_ID) + '"]')

    # Go through each "itype" entry 
    for name, itype in ANOMALI_TYPES.items():

        # Create a Host Group placeholder
        host_group_id = 0

        # Get the IPs from Anomali
        ip_array = queryAPI(itype)

        # If the length of the ip_array is more than one, then post the data to the SMC
        if len(ip_array) > 0:

            # Iterate through all the of the children of the parent Host Group to see if a child Host Group exists already
            for child_host_group in parent_host_group.findall('.//{http://www.lancope.com/sws/sws-service}host-group'):
                
                # If the Host Group name matches the Anomali name, then use it
                if name.lower() in child_host_group.get('name').lower():
                    host_group_id = child_host_group.get('id')

            # If the Host Group didn't exist, make a new one, otherwise, just update
            if host_group_id is 0:
                print("Submitting XML to the SMC for " + name + " and creating a new group")
                submitXMLToSMC(addHostGroupXML(ip_array, name))
            else:
                print("Submitting XML to the SMC for " + name + " and Group ID " + str(host_group_id))
                submitXMLToSMC(setHostGroupIPRangeXML(ip_array, host_group_id))
        else:
            # Print that we didn't find any data
            print("No IPs were found for the iType " + itype + "...")
#----------------------------------------------------#