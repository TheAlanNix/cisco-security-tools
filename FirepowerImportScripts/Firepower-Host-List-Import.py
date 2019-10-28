#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# Firepower-Host-List-Import.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 1.0
# Release Date: 08/10/2018
#
# Summary
# -------
#
# This script will take in a CSV list of Hosts an then import them into a Network Object in Firepower Management Center.
#
# Requirements
# ------------
#
#	1) Must have Python installed.
#	2) Must have 'requests' Python module installed.  Easiest way to do that:
#		- wget https://bootstrap.pypa.io/get-pip.py
#		- python get-pip.py		(may need to use 'sudo')
#		- pip install requests	(may need to use 'sudo')
#	3) Must have API access to a Firepower Management Console
#
# How To Run
# ----------
#
#	1) Configure the CSV_HOSTS_FILE variable 
#	2) Optionally, configure Firepower Management Console IP, Username, and Password
#		- If not statically set, the user will be prompted
#	2) Set this file to be executable.
#	3) Run it.
#
############################################################

import csv
import getpass
import logging
import json
import os
import requests

from requests.auth import HTTPBasicAuth
from pprint import pprint

# If receiving SSL Certificate Errors, un-comment the line below
#requests.packages.urllib3.disable_warnings()

####################
#  CONFIGURATION   #
####################
#
#----------------------------------------------------#
#

# Logging Parameters
logging.basicConfig(filename='Firepower-Host-List-Import.log', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filemode='w', level=logging.INFO)

# CSV Filename
CSV_HOSTS_FILE = "Example.csv"

# URL Placeholder
HOST_OBJECTS = []

# Firepower Management Console Variables
FMC_IP          = ""
FMC_USERNAME    = None
FMC_PASSWORD    = None
FMC_AUTH_TOKEN  = None
FMC_DOMAIN_UUID = None

#
#----------------------------------------------------#


####################
# !!! DO WORK !!!  #
####################


#----------------------------------------------------#
# A function to get the authentication token from the FMC
def getAuthTokenFMC():
    global FMC_AUTH_TOKEN, FMC_DOMAIN_UUID

    logging.info('Fetching Authentication Token from FMC...')

    # Build HTTP Authentication Instance
    auth = HTTPBasicAuth(FMC_USERNAME, FMC_PASSWORD)

    # Build HTTP Headers
    auth_headers = {'Content-Type': 'application/json'}

    # Build URL for Authentication
    auth_url = "https://{}/api/fmc_platform/v1/auth/generatetoken".format(FMC_IP)

    try:
        http_req = requests.post(url=auth_url, auth=auth, headers=auth_headers, verify=False)

        logging.debug('FMC Auth Response: ' + str(http_req.headers))

        FMC_AUTH_TOKEN = http_req.headers.get('X-auth-access-token', default=None)
        FMC_DOMAIN_UUID = http_req.headers.get('DOMAIN_UUID', default=None)

        # If we didn't get a token, then something went wrong
        if FMC_AUTH_TOKEN == None:
            print('Authentication Token Not Found...')
            logging.error('Authentication Token Not Found. Exiting...')
            exit()

        logging.info('Authentication Token Successfully Fetched.')

    except Exception as err:
        print('Error fetching auth token from FMC: ' + str(err))
        logging.error('Error fetching auth token from FMC: ' + str(err))
        exit()
#----------------------------------------------------#

#----------------------------------------------------#
# A function to modify an Object in the FMC
def ObjectCallFMC(method, endpoint, json_data=None):
    #print('Submitting ' + str(endpoint) + ' Object to the FMC via ' + str(method) + ' request. Data: ' + json.dumps(json_data))
    logging.info('Submitting ' + str(endpoint) + ' Object to the FMC via ' + str(method) + ' request. Data: ' + json.dumps(json_data))

    # If there's no FMC Authentication Token, then fetch one
    if FMC_AUTH_TOKEN == None:
        getAuthTokenFMC()

    # Build URL for Object endpoint
    endpoint_url = "https://{}/api/fmc_config/v1/domain/{}/object/{}".format(FMC_IP, FMC_DOMAIN_UUID, endpoint)

    # Build new headers with the access token
    headers = {'Content-Type': 'application/json', 'X-auth-access-token': FMC_AUTH_TOKEN}

    try:
        if method is 'POST':
            http_req = requests.post(url=endpoint_url, headers=headers, json=json_data, verify=False)
        elif method is 'PUT':
            http_req = requests.put(url=endpoint_url, headers=headers, json=json_data, verify=False)
        elif method is 'DELETE':
            http_req = requests.delete(url=endpoint_url, headers=headers, json=json_data, verify=False)
        else:
            http_req = requests.get(url=endpoint_url, headers=headers, json=json_data, verify=False)

        # Check to make sure the POST was successful
        if http_req.status_code >= 200 and http_req.status_code < 300:
            #print('Request succesfully sent to FMC.')
            logging.info('Request succesfully sent to FMC.')
            logging.debug('HTTP Response: ' + str(http_req.text))
            return http_req.json()
        else:
            print("FMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(http_req.status_code, http_req.json()))
            logging.error("FMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(http_req.status_code, http_req.json()))
            exit()

    except Exception as err:
        print('Error posting request to FMC: ' + str(err))
        logging.error('Error posting request to FMC: ' + str(err))
        exit()
#----------------------------------------------------#

#----------------------------------------------------#
# A function to parse CSV, manipulate it, and import it into FMC
if __name__ == "__main__":

    # Exit if the filename is empty
    if not CSV_HOSTS_FILE:
        logging.info('No file selected. Exiting...')
        exit()

    logging.info('Loading CSV file: ' + CSV_HOSTS_FILE)

    # Load in the CSV of URLs
    with open(CSV_HOSTS_FILE) as csv_file:

        # Open the CSV file
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0

        # Iterate through each line of the CSV
        for row in csv_reader:
            
            # Store the URL in an array
            HOST_OBJECTS.append({
                'value': row[0],
                'type': 'Host',
            })

            # Increment the line counter
            line_count += 1

    logging.info('Loaded ' + str(line_count) + ' Hosts.')

    # Ask the user for a name for the URL Group
    GROUP_NAME = input("Enter URL Group Name: ")

    # Format the data to be sent to the FMC
    NETWORK_OBJECT_JSON = {
        'type': 'NetworkGroup',
        'literals': HOST_OBJECTS,
        'overridable': True,
        'description': '',
        'name': GROUP_NAME,
    }

    logging.info(json.dumps(NETWORK_OBJECT_JSON))

    logging.info('Starting Network Object Import...')

    # If not hard coded, get the FMC IP, Username and Password
    if not FMC_IP:
        FMC_IP = input("FMC IP Address: ")
    if FMC_USERNAME is None:
        FMC_USERNAME = input("FMC Username: ")
    if FMC_PASSWORD is None:
        FMC_PASSWORD = getpass.getpass("FMC Password: ")

    # Post the URL Group object to the FMC
    print("Submitting URL Group to the FMC...")
    ObjectCallFMC('POST', 'networkgroups', NETWORK_OBJECT_JSON)
    exit()