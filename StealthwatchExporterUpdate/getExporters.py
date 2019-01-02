#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# getExporters.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 2.0
# Release Date: 01/02/2018
#
# Summary
# -------
#
# This script exports the "Exporters" out of StealthWatch into a CSV file
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
#   2) Run the script
#
############################################################

import csv
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

#
#----------------------------------------------------#


####################
# !!! DO WORK !!!  #
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
# A function to gather all exporters and export them to a CSV file.
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

    # Write all the Exporters to CSV
    with open('Exporter_IP_Output.csv', 'w') as csvoutput:

        # Set up the CSV output
        csv_writer = csv.writer(csvoutput)

        # Print out all the exporter IPs
        for exporter in exporters:
            print(exporter['ipAddress'])
            csv_writer.writerow([exporter['ipAddress']])
#----------------------------------------------------#