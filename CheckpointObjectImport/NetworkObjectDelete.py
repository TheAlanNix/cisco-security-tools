#!/usr/bin/env python2
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# NetworkObjectDelete.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 1.0
# Release Date: 09/11/2017
#
# Summary
# -------
#
# This script will delete all FMC objects that start with a specified pre-fix.
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
#   1) Configure Firepower Management Console IP and Credentials
#	2) Specify the Object Prefix
#
############################################################

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
logging.basicConfig(filename='NetworkObjectDelete.log', filemode='w', level=logging.INFO)

# Network Object Prefix
OBJECT_PREFIX   = "BOGUS_PREFIX"

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
# Afunction to get the authentication token from the FMC
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
    print('Submitting ' + str(endpoint) + ' Object to the FMC via ' + str(method) + ' request. Data: ' + json.dumps(json_data))
    logging.info('Submitting ' + str(endpoint) + ' Object to the FMC via ' + str(method) + ' request. Data: ' + json.dumps(json_data))

    # Build URL for Authentication
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
# A function to modify an Object in the FMC
def getAllObjectsFMC(endpoint):
    try:

        OBJECT_LIST = []

        # Query Loop Parameters
        query_limit = 50
        query_offset = 0
        object_count = query_limit

        # Loop through all Host objects
        while (object_count == query_limit):

            # Build a URL with the appropriate parameters
            url_endpoint = endpoint + "?offset={}&limit={}".format(query_offset, query_limit)

            # Get the objects from the FMC
            object_response = ObjectCallFMC('GET', url_endpoint)

            # Update the number of returned Host objects
            object_count = object_response['paging']['limit']

            if 'items' not in object_response.keys():
                break

            # Go through all hosts and see if they have the prefix
            for current_object in object_response['items']:

                # If the host begins with our prefix, then add it to our list
                if current_object['name'].startswith(OBJECT_PREFIX):
                    OBJECT_LIST.append(current_object['id'])

            # Increment the query offset
            query_offset += query_limit

        return OBJECT_LIST

    except Exception as err:
        logging.error(err)
#----------------------------------------------------#

#----------------------------------------------------#
# A function to get all objects, and delete the ones that match the specified prefix
if __name__ == "__main__":

    logging.info("Starting Network Object Delete...")

    # If not hard coded, get the FMC Username and Password
    if FMC_USERNAME is None:
        FMC_USERNAME = input("Firepower Username:")
    if FMC_PASSWORD is None:
        FMC_PASSWORD = getpass.getpass("Firepower Password:")

    # If there's no Authentication Token, then fetch one
    if FMC_AUTH_TOKEN == None:
        getAuthTokenFMC()

    # Get all of the objects that have the OBJECT_PREFIX
    network_groups = getAllObjectsFMC('networkgroups')

    print("Deleting {} Network Group Items...".format(len(network_groups)))

    # Go through the delete process for each entity
    for network_group in network_groups:

        # Build a URL with the appropriate parameters
        network_groups_endpoint = "networkgroups/{}".format(network_group)

        # Delete the Host object from the FMC
        network_groups_response = ObjectCallFMC('DELETE', network_groups_endpoint)

    # Get all of the objects that have the OBJECT_PREFIX
    hosts = getAllObjectsFMC('hosts')

    print("Deleting {} Host Items...".format(len(hosts)))

    # Go through the delete process for each entity
    for host in hosts:

        # Build a URL with the appropriate parameters
        hosts_endpoint = "hosts/{}".format(host)

        # Delete the Host object from the FMC
        hosts_response = ObjectCallFMC('DELETE', hosts_endpoint)

    # Get all of the objects that have the OBJECT_PREFIX
    networks = getAllObjectsFMC('networks')

    print("Deleting {} Network Items...".format(len(networks)))

    # Go through the delete process for each entity
    for network in networks:

        # Build a URL with the appropriate parameters
        networks_endpoint = "networks/{}".format(network)

        # Delete the Networks object from the FMC
        networks_response = ObjectCallFMC('DELETE', networks_endpoint)

    # Get all of the objects that have the OBJECT_PREFIX
    address_ranges = getAllObjectsFMC('ranges')

    print("Deleting {} Address Range Items...".format(len(address_ranges)))

    # Go through the delete process for each entity
    for address_range in address_ranges:

        # Build a URL with the appropriate parameters
        address_ranges_endpoint = "ranges/{}".format(address_range)

        # Delete the Address Range object from the FMC
        address_ranges_response = ObjectCallFMC('DELETE', address_ranges_endpoint)

    # Get all of the objects that have the OBJECT_PREFIX
    port_groups = getAllObjectsFMC('portobjectgroups')

    print("Deleting {} Port Group Items...".format(len(port_groups)))

    # Go through the delete process for each entity
    for port_group in port_groups:

        # Build a URL with the appropriate parameters
        port_groups_endpoint = "portobjectgroups/{}".format(port_group)

        # Delete the Port Group object from the FMC
        port_groups_response = ObjectCallFMC('DELETE', port_groups_endpoint)

    # Get all of the objects that have the OBJECT_PREFIX
    ports = getAllObjectsFMC('protocolportobjects')

    print("Deleting {} Port Items...".format(len(ports)))

    # Go through the delete process for each entity
    for port in ports:

        # Build a URL with the appropriate parameters
        ports_endpoint = "protocolportobjects/{}".format(port)

        # Delete the Port object from the FMC
        ports_response = ObjectCallFMC('DELETE', ports_endpoint)

