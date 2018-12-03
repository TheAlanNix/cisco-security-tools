#!/usr/bin/env python2
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# CP-to-FMC-Network-Object-Import.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 1.0
# Release Date: 09/19/2017
#
# Summary
# -------
#
# This script will use API calls in the Checkpoint manager to pull in Host, Network, Address Range and Group objects.
# We then manipulate those objects and import them into a Firepower Management Console (FMC)
#
# Requirements
# ------------
#
#   1) Must have Python installed.
#   2) Must have 'requests' Python module installed.  Easiest way to do that:
#     - wget https://bootstrap.pypa.io/get-pip.py
#     - python get-pip.py       (may need to use 'sudo')
#     - pip install requests    (may need to use 'sudo')
#   3) Must have API access to a Checkpoint SmartConsole
#   4) Must have API access to a Firepower Management Console
#
# How To Run
# ----------
#
#   1) Configure Checkpoint Manager IP
#       - Optionally, you can statically assign a username and password for "zero touch"
#   2) Configure Firepower Management Console IP
#       - Optionally, you can statically assign a username and password for "zero touch"
#   3) Set this file to be executable.
#   4) Run it.
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
logging.basicConfig(filename='CP-to-FMC-Network-Object-Import.log', filemode='w', level=logging.INFO)

# File Paramters
UUID_MAP_FILE = "network_objects_uuid_map.json"

# Object Prefix
OBJECT_PREFIX = ""

# Checkpoint Console Variables
CP_IP           = ""
CP_USERNAME     = None
CP_PASSWORD     = None
CP_AUTH_TOKEN   = None

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
# A function to get the authentication token from Checkpoint
def getAuthTokenCP():
    global CP_AUTH_TOKEN

    logging.info('Fetching Authentication Token from Checkpoint...')

     # Build HTTP Headers
    auth_headers = {'Content-Type': 'application/json'}

    # Build the Authentication JSON data
    auth_data = {'user': CP_USERNAME, 'password': CP_PASSWORD}

    # Build the Authentication URL
    auth_url = "https://{}/web_api/login".format(CP_IP)

    try:
        http_req = requests.post(url=auth_url, headers=auth_headers, json=auth_data, verify=False)

        logging.debug('Checkpoint Auth Response: ' + str(http_req.json()))

        CP_AUTH_TOKEN = http_req.json()
        CP_AUTH_TOKEN = CP_AUTH_TOKEN['sid']

        # If we didn't get a token, then something went wrong
        if CP_AUTH_TOKEN == None:
            print('Authentication Token Not Found...')
            logging.error('Authentication Token Not Found. Exiting...')
            exit()

        logging.info('Authentication Token Successfully Fetched.')

    except Exception as err:
        print('Error fetching auth token from Checkpoint: ' + str(err))
        logging.error('Error fetching auth token from Checkpoint: ' + str(err))
        exit()
#----------------------------------------------------#

#----------------------------------------------------#
# A function to get data from Checkpoint
def postObjectCallCP(endpoint, json_data=None):
    print('Fetching {} data from Checkpoint.'.format(endpoint))
    logging.info('Fetching {} data from Checkpoint.'.format(endpoint))

    # If there's no CP Authentication Token, then fetch one
    if CP_AUTH_TOKEN == None:
        getAuthTokenCP()

    # Build endpoint URL
    endpoint_url = "https://{}/web_api/{}".format(CP_IP, endpoint)

    # Build headers with the access token
    headers = {'Content-Type': 'application/json', 'X-chkp-sid': CP_AUTH_TOKEN}

    try:
        http_req = requests.post(url=endpoint_url, headers=headers, json=json_data, verify=False)

        # Check to make sure the POST was successful
        if http_req.status_code >= 200 and http_req.status_code < 300:
            logging.info('Request succesfully sent to Checkpoint.')
            logging.debug('HTTP Response: ' + str(http_req.text))
            return http_req.json()
        else:
            print("Checkpoint Connection Failure - HTTP Return Code: {}\nResponse: {}".format(http_req.status_code, http_req.json()))
            logging.error("Checkpoint Connection Failure - HTTP Return Code: {}\nResponse: {}".format(http_req.status_code, http_req.json()))
            exit()

    except Exception as err:
        print('Error posting request to Checkpoint: ' + str(err))
        logging.error('Error posting request to Checkpoint: ' + str(err))
        exit()
#----------------------------------------------------#

#----------------------------------------------------#
# A function to get all paginated data from Checkpoint
def getAllObjectsCP(endpoint):
    
    logging.info('Fetching all objects from the {} endpoint.'.format(endpoint))

    # Query Loop Parameters
    query_limit = 500
    query_offset = 0
    returned_objects = query_limit

    # Complete Object List
    object_list = []

    # Loop through all objects
    while (returned_objects == query_limit):

        # Build the post data
        pagination_data = {'limit': query_limit, 'offset': query_offset, "details-level": "full"}

        logging.info('Submitting request to {} with following parameters: {}'.format(endpoint, str(pagination_data)))

        # Get the objects from Checkpoint
        object_response = postObjectCallCP(endpoint, json_data=pagination_data)

        # Iterate through returned objects
        for current_object in object_response['objects']:

            # Append the current object chunk to our list
            object_list.append(current_object)

        # Update the number of returned objects
        returned_objects = len(object_response['objects'])

        # Increment the query offset
        query_offset += query_limit

    return object_list
#----------------------------------------------------#

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
    print('Submitting ' + str(endpoint) + ' Object to the FMC via ' + str(method) + ' request. Data: ' + json.dumps(json_data))
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
# A function to store our UUID translations to file
def storeUUIDs(uuid_map):
    with open(UUID_MAP_FILE, 'w') as output_file:
        json.dump(uuid_map, output_file)
#----------------------------------------------------#

#----------------------------------------------------#
# A function to parse JSON, manipulate it, and import it into FMC
if __name__ == "__main__":

    logging.info('Starting Network Object Import...')

    # If not hard coded, get the Checkpoint Username and Password
    if CP_USERNAME is None:
        CP_USERNAME = input("Checkpoint Username:")
    if CP_PASSWORD is None:
        CP_PASSWORD = getpass.getpass("Checkpoint Password:")

    # If not hard coded, get the FMC Username and Password
    if FMC_USERNAME is None:
        FMC_USERNAME = input("Firepower Username:")
    if FMC_PASSWORD is None:
        FMC_PASSWORD = getpass.getpass("Firepower Password:")

    logging.info('Fetching Network Objects from Checkpoint...')

    # Get all of the data sets from Checkpoint
    hosts_json          = getAllObjectsCP('show-hosts')
    networks_json       = getAllObjectsCP('show-networks')
    address_ranges_json = getAllObjectsCP('show-address-ranges')
    network_groups_json = getAllObjectsCP('show-groups')

    logging.info('Network Object Fetch Complete...')

    # If we have a stored UUID_MAP, then use it, otherwise create an empty one
    if os.path.isfile(UUID_MAP_FILE):

        # Open the UUID_MAP file and load it
        with open(UUID_MAP_FILE, 'r') as uuid_file:
            UUID_MAP = json.loads(uuid_file.read())
    else:
        # Make a placeholder UUID_MAP
        UUID_MAP = {
            'Group': {},
            'Host': {},
            'Network': {},
            'Range': {},
        }

    GROUP_OBJECTS = {}
    HOST_OBJECTS = {}
    NETWORK_OBJECTS = {}
    ADDRESS_RANGE_OBJECTS = {}

    logging.info('Transforming Host Object Data...')

    # Iterate through each Host object and transform it into FMC format
    for host in hosts_json:

        logging.info('Processing Host Object with UUID: {}'.format(host['uid']))

        # Check to see if we already imported this Host
        if host['uid'] not in UUID_MAP['Host'].keys():

            if 'ipv4-address' in host:
                value = host['ipv4-address']
            else:
                value = host['ipv6-address']

            # Add the host JSON to the host objects dictionary
            HOST_OBJECTS[host['uid']] = {
                'description': host['comments'],
                'name': OBJECT_PREFIX + host['name'],
                'type': 'Host',
                'value': value,
            }

    logging.info('Submitting Hosts to the Firepower Management Console...')

    # Post each Host to the FMC
    for host_uuid, host_json in HOST_OBJECTS.items():

        # Post the Host to the FMC and get the JSON response
        host_response = ObjectCallFMC('POST', 'hosts', host_json)

        # Store the UUID mapping for the newly created Host object
        UUID_MAP['Host'][host_uuid] = host_response['id']

        # Write the UUID_MAP to disk
        storeUUIDs(UUID_MAP)

    logging.info('Transforming Network Object Data...')

    # Iterate through each Network object and transform it into FMC format
    for network in networks_json:

        logging.info('Processing Network Object with UUID: {}'.format(network['uid']))

        # Check to see if we already imported this Network
        if network['uid'] not in UUID_MAP['Network'].keys():

            if 'subnet4' in network:
                value = network['subnet4'] + '/' + str(network['mask-length4'])
            else:
                value = network['subnet6'] + '/' + str(network['mask-length6'])

            # Add the network JSON to the network objects dictionary
            NETWORK_OBJECTS[network['uid']] = {
                'description': network['comments'],
                'name': OBJECT_PREFIX + network['name'],
                'type': 'Network',
                'value': value,
            }

    logging.info('Submitting Networks to the Firepower Management Console...')

    # Post each Network to the FMC
    for network_uuid, network_json in NETWORK_OBJECTS.items():

        # Post the Network to the FMC and get the JSON response
        network_response = ObjectCallFMC('POST', 'networks', network_json)

        # Store the UUID mapping for the newly created Network object
        UUID_MAP['Network'][network_uuid] = network_response['id']

        # Write the UUID_MAP to disk
        storeUUIDs(UUID_MAP)

    logging.info('Transforming Address Range Object Data...')

    # Iterate through each Address Range object and transform it into FMC format
    for address_range in address_ranges_json:

        logging.info('Processing Address Range Object with UUID: {}'.format(address_range['uid']))

        # Check to see if we already imported this Address Range
        if address_range['uid'] not in UUID_MAP['Range'].keys():

            if 'ipv4-address-first' in address_range:
                value = address_range['ipv4-address-first'] + '-' + address_range['ipv4-address-last']
            else:
                value = address_range['ipv6-address-first'] + '-' + address_range['ipv6-address-last']

            # Add the address range JSON to the address range objects dictionary
            ADDRESS_RANGE_OBJECTS[address_range['uid']] = {
                'description': address_range['comments'],
                'name': OBJECT_PREFIX + address_range['name'],
                'type': 'Range',
                'value': value,
            }

    logging.info('Submitting Address Ranges to the Firepower Management Console...')

    # Post each Address Range to the FMC
    for address_range_uuid, address_range_json in ADDRESS_RANGE_OBJECTS.items():

        # Post the Address Range to the FMC and get the JSON response
        address_range_response = ObjectCallFMC('POST', 'ranges', address_range_json)

        # Store the UUID mapping for the newly created Address Range object
        UUID_MAP['Range'][address_range_uuid] = address_range_response['id']

        # Write the UUID_MAP to disk
        storeUUIDs(UUID_MAP)

    logging.info('Transforming Network Group Data...')

    # Iterate through each Group object and transform it into FMC format
    for group in network_groups_json:

        logging.info('Processing Group Object with UUID: {}'.format(group['uid']))

        # Check to see if we already imported the Group
        if group['uid'] not in UUID_MAP['Group'].keys():

            # Add the group JSON to the group objects dictionary
            GROUP_OBJECTS[group['uid']] = {
                'description': group['comments'],
                'name': OBJECT_PREFIX + group['name'],
                'objects': [],
            }

            # Add each member's UUID to the objects of the group dictionary
            for member in group['members']:

                if member['uid'] in UUID_MAP['Host'].keys() or member['uid'] in UUID_MAP['Network'].keys() or member['uid'] in UUID_MAP['Range'].keys():

                    # Get the member type and capitalize the first letter
                    member_type = member['type'].title()

                    # Checkpoint calls ranges "Address-Range" - so convert it
                    if member_type == "Address-Range":
                        member_type = "Range"

                    # Add the translated object UUID to the objects list
                    GROUP_OBJECTS[group['uid']]['objects'].append({
                        'type': member_type,
                        'id': UUID_MAP[member_type][member['uid']],
                    })

                else:
                    continue

    # Post each Group to the FMC
    for group_uuid, group_json in GROUP_OBJECTS.items():

        # Post the Group to the FMC and get the JSON response
        group_response = ObjectCallFMC('POST', 'networkgroups', group_json)

        # Store the UUID mapping for the newly created Group object
        UUID_MAP['Group'][group_uuid] = group_response['id']

        # Write the UUID_MAP to disk
        storeUUIDs(UUID_MAP)