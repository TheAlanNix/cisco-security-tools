#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# FirepowerPolicyToCSV.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 1.0
# Release Date: 12/03/2018
#
# Summary
# -------
#
# This script will connect to the Firepower Management Center and then export the specified policy to CSV.
#
# Requirements
# ------------
#
#   1) Must have Python installed.
#   2) Must have 'requests' Python module installed.  Easiest way to do that:
#       - wget https://bootstrap.pypa.io/get-pip.py
#       - python get-pip.py		(may need to use 'sudo')
#       - pip install requests	(may need to use 'sudo')
#   3) Must have API access to a Firepower Management Console
#
# How To Run
# ----------
#
#
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
logging.basicConfig(filename='FirepowerPolicyToCSV.log', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filemode='w', level=logging.INFO)

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
def getAuthToken():
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
# A function to call the FMC API
def Call_FMC_API(method, endpoint, json_data=None):

    # If there's no FMC Authentication Token, then fetch one
    if FMC_AUTH_TOKEN == None:
        getAuthToken()

    logging.info('Submitting ' + str(endpoint) + ' Object to the FMC via ' + str(method) + ' request. Data: ' + json.dumps(json_data))

    # Build URL for Object endpoint
    endpoint_url = "https://{}/api/fmc_config/v1/domain/{}/{}".format(FMC_IP, FMC_DOMAIN_UUID, endpoint)

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
# A function to call the FMC API and get all paginated results
def Call_FMC_API_All(endpoint):

    logging.info('Fetching all objects from the {} endpoint.'.format(endpoint))

    # Query Loop Parameters
    query_limit = 25
    query_offset = 0
    returned_objects = query_limit

    # Complete Object List
    item_list = []

    # Loop through all objects
    while (returned_objects == query_limit):

        # Build the URL
        paginated_url = endpoint + "?limit={}&offset={}&expanded=true".format(query_limit, query_offset)

        logging.info('Submitting request to {}'.format(paginated_url))

        # Get the objects from the FMC
        fmc_response = Call_FMC_API('GET', paginated_url)

        if 'items' not in fmc_response:
            break

        # Iterate through returned item
        for item in fmc_response['items']:

            # Append the current item chunk to our list
            item_list.append(item)

        # Update the number of returned objects
        returned_objects = len(fmc_response['items'])

        # Increment the query offset
        query_offset += query_limit

    return item_list
#----------------------------------------------------#

#----------------------------------------------------#
# A function to parse the JSON returned by the FMC into something that can be written to a CSV file
def parse_policy_line(access_rule):

    logging.info("Parsing Access Control Rule...")

    return_json = {}

    # Enabled
    return_json['enabled'] = access_rule['enabled']

    # Name
    return_json['name'] = access_rule['name']

    # Source Zones
    zone_list = []

    if 'sourceZones' in access_rule:

        for zone in access_rule['sourceZones']['objects']:
            zone_list.append(zone['name'])

    return_json['source_zones'] = zone_list

    # Destination Zones
    zone_list = []
    
    if 'destinationZones' in access_rule:

        for zone in access_rule['destinationZones']['objects']:
            zone_list.append(zone['name'])

    return_json['destination_zones'] = zone_list

    # Source Networks
    network_list = []

    if 'sourceNetworks' in access_rule:

        for network in access_rule['sourceNetworks']['objects']:
            network_list.append(network['name'])

    return_json['source_networks'] = network_list

    # Destination Networks
    network_list = []

    if 'destinationNetworks' in access_rule:

        for network in access_rule['destinationNetworks']['objects']:
            network_list.append(network['name'])

    return_json['destination_networks'] = network_list

    # VLAN Tags
    vlan_list = []

    if 'vlanTags' in access_rule:

        for vlan in access_rule['vlanTags']:
            vlan_list.append(vlan)

    return_json['vlan_tags'] = vlan_list

    # Users
    user_list = []

    if 'users' in access_rule:

        for user in access_rule['users']['objects']:
            user_list.append(user['name'])

    return_json['users'] = user_list

    # Applications
    application_list = []

    if 'applications' in access_rule:

        for application in access_rule['applications']['applications']:
            application_list.append(application['name'])

    return_json['applications'] = application_list

    # Source Ports
    port_list = []

    if 'sourcePorts' in access_rule:

        if 'literals' in access_rule['sourcePorts']:
            for port in access_rule['sourcePorts']['literals']:

                # Check for ICMP
                if port['protocol'] == "1":
                    port_list.append("ICMP ({})".format(port['icmpType']))

                # Check for TCP
                if port['protocol'] == "6":
                    port_list.append("{}/TCP".format(port['port']))

                # Check for UDP
                if port['protocol'] == "17":
                    port_list.append("{}/UDP".format(port['port']))

        if 'objects' in access_rule['sourcePorts']:
            for port in access_rule['sourcePorts']['objects']:
                port_list.append(port['name'])

    return_json['source_ports'] = port_list

    # Destination Ports
    port_list = []

    if 'destinationPorts' in access_rule:

        if 'literals' in access_rule['destinationPorts']:
            for port in access_rule['destinationPorts']['literals']:

                # Check for ICMP
                if port['protocol'] == "1":
                    port_list.append("ICMP ({})".format(port['icmpType']))

                # Check for TCP
                if port['protocol'] == "6":
                    port_list.append("{}/TCP".format(port['port']))

                # Check for UDP
                if port['protocol'] == "17":
                    port_list.append("{}/UDP".format(port['port']))

        if 'objects' in access_rule['destinationPorts']:
            for port in access_rule['destinationPorts']['objects']:
                port_list.append(port['name'])

    return_json['destination_ports'] = port_list

    # URLs
    url_list = []

    if 'urls' in access_rule:

        if 'objects' in access_rule['urls']:

            for category in access_rule['urls']['objects']:
                url_list.append(category['name'])

        if 'urlCategoriesWithReputation' in access_rule['urls']:

            for category in access_rule['urls']['urlCategoriesWithReputation']:
                url_list.append(category['category']['name'])

    return_json['urls'] = url_list

    # ISE/SGT Attributes
    ise_list = []

    if 'sourceSecurityGroupTags' in access_rule:
        for sgt in access_rule['sourceSecurityGroupTags']['objects']:
            ise_list.append(sgt['name'])

    if 'endPointDeviceTypes' in access_rule:
        for endpoint in access_rule['endPointDeviceTypes']:
            ise_list.append(endpoint['name'])

    return_json['ise_sgt'] = ise_list

    # Action
    return_json['action'] = access_rule['action']

    # IPS Policy
    return_json['ips_policy'] = ""
    
    if 'ipsPolicy' in access_rule:
        return_json['ips_policy'] = access_rule['ipsPolicy']['name']

    # File Policy
    return_json['file_policy'] = ""
    
    if 'filePolicy' in access_rule:
        return_json['file_policy'] = access_rule['filePolicy']['name']

    # Logging
    return_json['logging'] = access_rule['logBegin'] or access_rule['logEnd']

    return return_json
#----------------------------------------------------#

#----------------------------------------------------#
# A function to parse CSV, manipulate it, and import it into FMC
if __name__ == "__main__":

    # If not hard coded, get the FMC IP, Username and Password
    if not FMC_IP:
        FMC_IP = input("FMC IP Address: ")
    if FMC_USERNAME is None:
        FMC_USERNAME = input("FMC Username: ")
    if FMC_PASSWORD is None:
        FMC_PASSWORD = getpass.getpass("FMC Password: ")

    # Fetch all policies from the FMC
    policies_json = Call_FMC_API_All('policy/accesspolicies')

    print("\nPlease select one of the following policies to export:\n")

    policy_index = 1

    # Print the policy options that are available
    for policy in policies_json:
        print("{}) {}".format(policy_index, policy['name']))
        policy_index += 1

    # Prompt the user for the policy
    selected_policy = input("\nPolicy Selection: ")

    # Make sure that the selected policy was valid
    if 0 < int(selected_policy) <= len(policies_json):
        selected_policy = int(selected_policy) - 1
    else:
        print("ERROR: Policy selection was not correct.")
        exit()

    filename = policies_json[selected_policy]["name"] + " export.csv"

    print("Working...")

    # Create a CSV file to write to
    with open(filename, mode='w') as csv_file:
        fieldnames = ['enabled', 'name', 'source_zones', 'destination_zones', 'source_networks', 'destination_networks', 'vlan_tags', 'users',
            'applications', 'source_ports', 'destination_ports', 'urls', 'ise_sgt', 'action', 'ips_policy', 'file_policy', 'logging']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        writer.writeheader()

        # Get the policy rules from the FMC
        policy_json = Call_FMC_API_All('policy/accesspolicies/{}/accessrules'.format(policies_json[selected_policy]["id"]))

        # Iterate through the selected policy
        for policy_rule in policy_json:

            # Write the ACLs to the CSV file
            writer.writerow(parse_policy_line(policy_rule))

    print("Done!")
    logging.info("Complete!")
#----------------------------------------------------#