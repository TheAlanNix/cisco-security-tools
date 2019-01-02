#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# Talos_Blacklist_Import.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 2.0
# Release Date: 01/02/2018
#
# Summary
# -------
#
# This script allows you to import blacklisted IPs from Talos
#
#
# Requirements
# ------------
#
#   1) Must have Python installed.
#   2) Must have 'requests' Python module installed.  Easiest way to do that:
#     - wget https://bootstrap.pypa.io/get-pip.py
#     - python get-pip.py       (may need to use 'sudo')
#     - pip install requests    (may need to use 'sudo')
#
# How To Run
# ----------
#
#   1) Configure StealthWatch SW_DOMAIN_ID, SW_SMC_IP, SW_USERNAME, SW_PASSWORD
#   2) Configure HOSTGROUP_ID where you want the list imported
#   3) Run the script / set a cron job
#
############################################################

import getpass
import json
import requests

from requests.auth import HTTPBasicAuth
from requests.packages import urllib3

# Disable SSL Cert warnings
urllib3.disable_warnings()

####################
#  CONFIGURATION   #
####################
#
#----------------------------------------------------#
#

# Setup an API session
API_SESSION     = requests.Session()

# Build file references
LIST_URL = "http://www.talosintel.com/feeds/ip-filter.blf"

# StealthWatch SMC Variables
SW_DOMAIN_ID = None
SW_SMC_IP    = ""
SW_USERNAME  = ""
SW_PASSWORD  = ""

# Talos Host Group ID
HOSTGROUP_ID = 76

#
#----------------------------------------------------#


####################
# !!! DO WORK !!!  #
####################

#----------------------------------------------------#
# Get REST API Token
def getAccessToken():

    # The URL to authenticate to the SMC
    url = "https://{}/token/v2/authenticate".format(SW_SMC_IP)

    print('Stealthwatch login URL: ' + url)

    # JSON to hold the authentication credentials
    login_credentials = {
        "username": SW_USERNAME,
        "password": SW_PASSWORD
    }

    try:
        # Make an authentication request to the SMC
        response = API_SESSION.post(url, data=login_credentials, verify=False)

        # If the request was successful, then proceed
        if response.status_code == 200:
            print('Successfully Authenticated.')
            return response.text
        else:
            print('SMC Connection Failure - HTTP Return Code: {}\nResponse: {}'.format(response.status_code, response.text))
            exit()

    except Exception as err:
        print('Unable to post to the SMC - Error: {}'.format(err))
        exit()
#----------------------------------------------------#

#----------------------------------------------------#
# Get the "tenants" (domains) from Stealthwatch
def getTenants():

    global SW_DOMAIN_ID

    # The URL to get tenants
    url = 'https://{}/sw-reporting/v1/tenants/'.format(SW_SMC_IP)

    # Get the tenants
    response = API_SESSION.get(url, verify=False)

    # If the request was successful, then proceed
    if response.status_code == 200:

        # Parse the response as JSON
        tenants = json.loads(response.text)
        tenants = tenants['data']

        # Set the Domain ID if theres only one, or prompt the user if there are multiple
        if len(tenants) == 1:
            SW_DOMAIN_ID = tenants[0]['id']
        else:
            print("\nPlease select one of the following Domains:\n")

            domain_index = 1

            # Print the domain options that are available
            for tenant in tenants:
                print("{}) {}".format(domain_index, tenant['displayName']))
                domain_index += 1

            # Prompt the user for the Domain
            selected_domain = input("\nDomain Selection: ")

            # Make sure that the selected domain was valid
            if 0 < int(selected_domain) <= len(tenants):
                selected_domain = int(selected_domain) - 1
            else:
                print("ERROR: Domain selection was not correct.")
                exit()

            SW_DOMAIN_ID = tenants[selected_domain]['id']

    else:
        print('SMC Connection Failure - HTTP Return Code: {}\nResponse: {}'.format(response.status_code, response.text))
        exit()
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
        if http_req.status_code >= 200 and http_req.status_code < 300:
            print('Success.')
        else:
            print('SMC Connection Failure - HTTP Return Code: {}\nResponse: {}'.format(http_req.status_code, http_req.json()))
            exit()

    except Exception as err:
        print('Unable to post to the SMC - Error: {}'.format(err))
        exit()
#----------------------------------------------------#

#----------------------------------------------------#
# A function to get the Talos threat feed and then import it into Stealthwatch
if __name__ == "__main__":

    # If not hard coded, get the SMC IP, Username and Password
    if not SW_SMC_IP:
        SW_SMC_IP = input("SMC IP/FQDN Address: ")
    if not SW_USERNAME:
        SW_USERNAME = input("SMC Username: ")
    if not SW_PASSWORD:
        SW_PASSWORD = getpass.getpass("SMC Password: ")

    # If a Domain ID wasn't specified, then get one
    if SW_DOMAIN_ID is None:

        # Authenticate to REST API
        getAccessToken()

        # Get Tenants from REST API
        getTenants()

    # Create an IP array
    ip_array = []

    print("Fetching new IP data from Talos...")

    # Get the IP data from Talos
    response = requests.get(LIST_URL, stream=True)

    # Add each IP address to our ip_array
    for line in response.iter_lines():
        if line:
            ip_array.append(line)

    # Make the XML and submit to the SMC
    submitXMLToSMC(setHostGroupIPRangeXML(ip_array, HOSTGROUP_ID))
#----------------------------------------------------#
