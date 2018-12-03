#!/usr/bin/env python2
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# CP-to-FMC-Service-Object-Import.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 1.0
# Release Date: 09/19/2017
#
# Summary
# -------
#
# This script will use API calls in the Checkpoint manager to pull in TCP Services, UDP Services, and Service Group objects.
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
logging.basicConfig(filename='CP-to-FMC-Service-Object-Import.log', filemode='w', level=logging.INFO)

# File Paramters
UUID_MAP_FILE = "service_objects_uuid_map.json"

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
# A function parse JSON, manipulate it, and import it into FMC
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

    logging.info('Fetching Service Objects from Checkpoint...')

    # Get all of the data sets from Checkpoint
    services_tcp_json   = getAllObjectsCP('show-services-tcp')
    services_udp_json   = getAllObjectsCP('show-services-udp')
    service_groups_json = getAllObjectsCP('show-service-groups')

    logging.info('Service Object Fetch Complete...')

    # If we have a stored UUID_MAP, then use it, otherwise create an empty one
    if os.path.isfile(UUID_MAP_FILE):

        # Open the UUID_MAP file and load it
        with open(UUID_MAP_FILE, 'r') as uuid_file:
            UUID_MAP = json.loads(uuid_file.read())
    else:
        # Make a placeholder UUID_MAP
        UUID_MAP = {
            'ProtocolPortObject': {},
            'PortObjectGroup': {},
        }

    PORT_OBJECTS = {}
    GROUP_OBJECTS = {}

    logging.info('Transforming TCP Service Object Data...')

    # Iterate through each TCP Service object and transform it into FMC format
    for service_tcp in services_tcp_json:

        logging.info('Processing TCP Service Object with UUID: {}'.format(service_tcp['uid']))

        # Check to see if we already imported this Service
        if service_tcp['uid'] not in UUID_MAP['ProtocolPortObject'].keys():

            # Checkpoint allows some logic functions, FMC does not.
            if ">" in service_tcp['port']:
                continue

            # Add the Port JSON to the port objects dictionary
            PORT_OBJECTS[service_tcp['uid']] = {
                'name': OBJECT_PREFIX + service_tcp['name'],
                'protocol': "TCP",
                'port': service_tcp['port'],
                'type': 'ProtocolPortObject',
            }

    logging.info('Transforming UDP Service Object Data...')

    # Iterate through each UDP Service object and transform it into FMC format
    for service_udp in services_udp_json:

        logging.info('Processing UDP Service Object with UUID: {}'.format(service_udp['uid']))

        # Check to see if we already imported this Service
        if service_udp['uid'] not in UUID_MAP['ProtocolPortObject'].keys():

            # Checkpoint allows some logic functions, FMC does not.
            if ">" in service_udp['port']:
                continue

            # Add the Port JSON to the port objects dictionary
            PORT_OBJECTS[service_udp['uid']] = {
                'name': OBJECT_PREFIX + service_udp['name'],
                'protocol': "UDP",
                'port': service_udp['port'],
                'type': 'ProtocolPortObject',
            }

    logging.info('Submitting Port Objects to the Firepower Management Console...')

    # Post each Port to the FMC
    for port_uuid, port_json in PORT_OBJECTS.items():

        # Post the Port to the FMC and get the JSON response
        port_response = ObjectCallFMC('POST', 'protocolportobjects', port_json)

        # Store the UUID mapping for the newly created Host object
        UUID_MAP['ProtocolPortObject'][port_uuid] = port_response['id']

        # Write the UUID_MAP to disk
        storeUUIDs(UUID_MAP)

    logging.info('Transforming Service Group Data...')

    # Iterate through each Service Group object and transform it into FMC format
    for group in service_groups_json:

        logging.info('Processing Service Group Object with UUID: {}'.format(group['uid']))

        # Check to see if we already imported the Service Group
        if group['uid'] not in UUID_MAP['PortObjectGroup'].keys():

            # Add the Port Group JSON to the port group objects dictionary
            GROUP_OBJECTS[group['uid']] = {
                'name': OBJECT_PREFIX + group['name'],
                'objects': [],
                'type': 'PortObjectGroup',
            }

            # Add each member's UUID to the objects of the group dictionary
            for member in group['members']:

                if member['uid'] in UUID_MAP['ProtocolPortObject'].keys():

                    # Get the member type and capitalize the first letter
                    member_type = member['type'].title()

                    # Add the translated object UUID to the objects list
                    GROUP_OBJECTS[group['uid']]['objects'].append({
                        'type': "ProtocolPortObject",
                        'id': UUID_MAP["ProtocolPortObject"][member['uid']],
                    })

                else:
                    continue
                    ###### ITERATE THROUGH THE GROUP MEMBER HERE #######

    # Post each Group to the FMC
    for group_uuid, group_json in GROUP_OBJECTS.items():

        # Post the Group to the FMC and get the JSON response
        group_response = ObjectCallFMC('POST', 'portobjectgroups', group_json)

        # Store the UUID mapping for the newly created Group object
        UUID_MAP['PortObjectGroup'][group_uuid] = group_response['id']

        # Write the UUID_MAP to disk
        storeUUIDs(UUID_MAP)