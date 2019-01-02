#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# bulkDeleteExporters.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 2.0
# Release Date: 01/02/2018
#
# Summary
# -------
#
# This script gets the exporters out of StealthWatch, compares it to a whitelist, 
# and then deletes exporters that don't exist in the configured Whitelist.
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
#   1) Optionally configure StealthWatch SW_SMC_ADDRESS, SW_USERNAME, SW_PASSWORD
#   2) Configure EXPORTER_WHITELIST array to contain the Exporters you'd like to keep
#   3) Run the script
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

# StealthWatch SMC Variables
SW_DOMAIN_ID    = None
SW_SMC_ADDRESS  = ""
SW_USERNAME     = ""
SW_PASSWORD     = ""

# Exporter Whitelist
EXPORTER_WHITELIST = [
    "192.168.1.1"
]

#
#----------------------------------------------------#


####################
#    FUNCTIONS     #
####################

#----------------------------------------------------#
# Get REST API Token
def getAccessToken():

    # The URL to authenticate to the SMC
    url = "https://" + SW_SMC_ADDRESS + "/token/v2/authenticate"

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
    url = 'https://' + SW_SMC_ADDRESS + '/sw-reporting/v1/tenants/'

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
# Get the Exporters from Stealthwatch
def getExporters():

    # The URL to get Exporters
    url = 'https://{}/sw-reporting/v1/tenants/{}/netops/exporters/details/True'.format(SW_SMC_ADDRESS, SW_DOMAIN_ID)

    # Get the Exporters
    response = API_SESSION.get(url, verify=False)

    # If the request was successful, then proceed
    if response.status_code == 200:

        # Parse the response as JSON
        exporters = json.loads(response.text)
        exporters = exporters['data']

        return exporters

    else:
        print('SMC Connection Failure - HTTP Return Code: {}\nResponse: {}'.format(response.status_code, response.text))
        exit()
#----------------------------------------------------#

#----------------------------------------------------#
# A function to build removeExporters XML for the SMC
def removeExportersXML(exporter_dict):

    # Build the XML
    return_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    return_xml += "<soapenc:Envelope xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
    return_xml += "\t<soapenc:Body>\n"
    return_xml += "\t\t<removeExporters>\n"
    return_xml += "\t\t\t<domain id=\"{}\">\n".format(SW_DOMAIN_ID)
    return_xml += "\t\t\t\t<swa-list>\n"

    # Iterate through the FlowCollectors
    for flowcollector in exporter_dict.keys():
        return_xml += "\t\t\t\t\t<swa id=\"{}\">\n".format(flowcollector)
        return_xml += "\t\t\t\t\t\t<exporter-list>\n"

        # Iterate through the Exporters for the FlowCollector
        for exporter in exporter_dict[flowcollector]:
            return_xml += "\t\t\t\t\t\t\t<exporter ip=\"{}\" />\n".format(exporter)

        return_xml += "\t\t\t\t\t\t</exporter-list>\n"
        return_xml += "\t\t\t\t\t</swa>\n"

    return_xml += "\t\t\t\t</swa-list>\n"
    return_xml += "\t\t\t</domain>\n"
    return_xml += "\t\t</removeExporters>\n"
    return_xml += "\t</soapenc:Body>\n"
    return_xml += "</soapenc:Envelope>"

    return return_xml
#----------------------------------------------------#

#----------------------------------------------------#
# A function to post supplied XML to the SMC
def submitXMLToSMC(xml):

    # Build the SMC URL
    SMC_URL = "https://{}/smc/swsService/configuration".format(SW_SMC_ADDRESS)

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
            print('SMC Connection Failure - HTTP Return Code: {}\nResponse: {}'.format(http_req.status_code, http_req.text))
            exit()
    except Exception as err:
        print('Unable to post to the SMC - Error: {}'.format(err))
        exit()
#----------------------------------------------------#


####################
# !!! DO WORK !!!  #
####################

#----------------------------------------------------#
# A function to gather all exporters, and remove the ones that are not whitelisted.
if __name__ == "__main__":

    # If not hard coded, get the SMC IP, Username and Password
    if not SW_SMC_ADDRESS:
        SW_SMC_ADDRESS = input("SMC IP/FQDN Address: ")
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

    # Get all exporters from the SMC
    exporters = getExporters()

    # Set up an exporters purge dictionary
    exporter_purge_dict = {}

    # Iterate through each exporter
    for exporter in exporters:

        # Store the FlowCollector ID
        SWA_ID = exporter['swaId']

        # Ignore FlowSensors
        if 'FLOW_SENSOR' not in exporter['type']:

            # Ignore Whitelisted Exporters
            if exporter['ipAddress'] not in EXPORTER_WHITELIST:

                # If we haven't seen this FlowCollector before, then initialize it in our dictionary
                if SWA_ID not in exporter_purge_dict.keys():
                    exporter_purge_dict[SWA_ID] = []

                # Add the exporter to our dictionary
                exporter_purge_dict[SWA_ID].append(exporter['ipAddress'])

    # Get removeExportersXML based on the array, and then send it to the SMC

    # TESTING - Prints the XML for review
    print(removeExportersXML(exporter_purge_dict))

    # PRODUCTION - Submits the XML to the SMC
    #print(submitXMLToSMC(removeExportersXML(exporter_purge_dict)))
#----------------------------------------------------#