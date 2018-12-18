#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# FirepowerEnableLogging.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 1.0
# Release Date: 12/17/2018
#
# Summary
# -------
#
# This script will connect to the Firepower Management Center and then enable logging on all rules in a selected access policy.
# Currently this only works with Firepower 6.3.
#
# Requirements
# ------------
#
#   1) Must have Python installed.
#   2) Must have 'requests' Python module installed.  Easiest way to do that:
#       - wget https://bootstrap.pypa.io/get-pip.py
#       - python get-pip.py     (may need to use 'sudo')
#       - pip install requests  (may need to use 'sudo')
#   3) Must have API access to a Firepower Management Console
#
# How To Run
# ----------
#
#   1) First, MAKE A COPY OF THE ACCESS POLICY THAT YOU WANT TO USE! (Just in case)
#   2) Run this script with Python 3.x
#
############################################################

import getpass
import logging
import json
import requests

from requests.auth import HTTPBasicAuth
from pprint import pprint

# If receiving SSL Certificate Errors, un-comment the line below
requests.packages.urllib3.disable_warnings()

####################
#  CONFIGURATION   #
####################
#
#----------------------------------------------------#
#

# Logging Parameters
logging.basicConfig(filename='FirepowerEnableLogging.log', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filemode='w', level=logging.INFO)

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
# A function to get an authentication token from the FMC
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

        logging.debug('FMC Auth Response:\n{}'.format(http_req.headers))

        # Store the auth token
        FMC_AUTH_TOKEN = http_req.headers.get('X-auth-access-token', default=None)
        
        # Let the user pick the domain
        domain_data = json.loads(http_req.headers.get('DOMAINS', default=None))
        FMC_DOMAIN_UUID = Process_Domains(domain_data)

        # If we didn't get a token, then something went wrong
        if FMC_AUTH_TOKEN == None:
            print('Authentication Token Not Found...')
            logging.error('Authentication Token Not Found. Exiting...')
            exit()

        logging.info('Authentication Token Successfully Fetched.')
        logging.debug('Auth Token: {}'.format(FMC_AUTH_TOKEN))

    except Exception as err:
        print('Error fetching auth token from FMC: ' + str(err))
        logging.error('Error fetching auth token from FMC: ' + str(err))
        exit()
#----------------------------------------------------#

#----------------------------------------------------#
# A function to parse the domains returned by the FMC
def Process_Domains(domain_list):

    RETURN_UUID = None

    # If there's only one domain then default to that, otherwise ask the user
    if len(domain_list) == 1:
        RETURN_UUID = domain_list[0]["uuid"]
    else:
        print("\nPlease select the FMC Domain you'd like to use:\n")

        domain_index = 1

        # Print the domain options that are available
        for domain in domain_list:
            print("{}) {}".format(domain_index, domain['name']))
            domain_index += 1
        
        # Prompt the user for the domain
        selected_domain = input("\nDomain Selection: ")

        # Make sure that the selected domain was valid
        if 0 < int(selected_domain) <= len(domain_list):
            RETURN_UUID = domain_list[int(selected_domain) - 1]['uuid']
        else:
            print("ERROR: Domain selection was not valid.")
            exit()

    return RETURN_UUID
#----------------------------------------------------#

#----------------------------------------------------#
# A function to call the FMC API
def Call_FMC_API(method, endpoint, json_data=None):

    # If there's no FMC Authentication Token, then fetch one
    if FMC_AUTH_TOKEN == None:
        getAuthToken()

    if method in ['GET', 'DELETE']:
        logging.info('Submitting {} resource call to the FMC via {} request.'.format(endpoint, method))
    else:
        logging.info('Submitting {} resource call to the FMC via {} request. Data:\n{}'.format(endpoint, method, json.dumps(json_data, indent=4)))

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
            logging.info('Request succesfully sent to FMC.')
            logging.debug('HTTP Response:\n{}'.format(http_req.text))
            return http_req.json()
        else:
            print("FMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(http_req.status_code, http_req.json()))
            logging.error("FMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(http_req.status_code, http_req.json()))
            exit()

    except Exception as err:
        print('Error posting request to FMC: {}'.format(err))
        logging.error('Error posting request to FMC: {}'.format(err))
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

    logging.debug('All paginated results from {}:\n{}'.format(endpoint, item_list))

    return item_list
#----------------------------------------------------#

#----------------------------------------------------#
# A function to enable logging on all rules within an Access Control Policy
if __name__ == "__main__":

    # If not hard coded, get the FMC IP, Username and Password
    if not FMC_IP:
        FMC_IP = input("FMC IP Address: ")
    if FMC_USERNAME is None:
        FMC_USERNAME = input("FMC Username: ")
    if FMC_PASSWORD is None:
        FMC_PASSWORD = getpass.getpass("FMC Password: ")

    # Fetch all policies from the FMC
    access_policies = Call_FMC_API_All('policy/accesspolicies')

    print("\nPlease select one of the following policies to export:\n")

    policy_index = 1

    # Print the policy options that are available
    for policy in access_policies:
        print("{}) {}".format(policy_index, policy['name']))
        policy_index += 1

    # Prompt the user for the policy
    selected_policy = input("\nPolicy Selection: ")

    # Make sure that the selected policy was valid
    if 0 < int(selected_policy) <= len(access_policies):
        selected_policy = int(selected_policy) - 1
    else:
        print("ERROR: Policy selection was not correct.")
        exit()

    print("Working...")

    ######### TODO #########
    # The API for the FMC currently isn't letting me change the default action logging
    #
    #    # Get the Default Actions for the Access Policy
    #    default_actions = Call_FMC_API('GET', 'policy/accesspolicies/{}/defaultactions?expanded=true'.format(access_policies[selected_policy]["id"]))
    #    default_actions = default_actions['items'][0]
    #
    #    # Log the response
    #    logging.info("Orignial Default Actions:\n{}".format(json.dumps(default_actions, indent=4)))
    #
    #    # Drop the metadata
    #    default_actions.pop("metadata")
    #
    #    # Set the new Default Actions
    #    default_actions["logBegin"] = True
    #    default_actions["logEnd"] = True
    #    default_actions["sendEventsToFMC"] = True
    #
    #    # Update the Default Actions on the FMC
    #    default_actions = Call_FMC_API('PUT', 'policy/accesspolicies/{}/defaultactions'.format(access_policies[selected_policy]["id"]), json_data=default_actions)
    #
    #    # Log the response
    #    logging.info("New Default Actions:\n{}".format(json.dumps(default_actions, indent=4)))

    # Get the policy rules from the FMC
    access_policy_rules = Call_FMC_API_All('policy/accesspolicies/{}/accessrules'.format(access_policies[selected_policy]["id"]))

    # Iterate through all rules and enable logging
    for access_rule in access_policy_rules:

        print("Updating Rule '{}'...".format(access_rule["name"]))

        # Remove unique data
        access_rule.pop("metadata")
        access_rule.pop("links")

        # Check to see if Users are used in the rules, and if so, remove the realms (the FMC barfs if they exist)
        if "users" in access_rule:
            if "objects" in access_rule["users"]:

                # Iterate through the user objects and remove the realm key
                for user_object in access_rule["users"]["objects"]:
                    user_object.pop("realm")

        # Enable all logging
        access_rule["enableSyslog"] = True
        access_rule["logBegin"] = True
        access_rule["logEnd"] = True
        access_rule["sendEventsToFMC"] = True

        Call_FMC_API('PUT', 'policy/accesspolicies/{}/accessrules/{}'.format(access_policies[selected_policy]["id"], access_rule["id"]), json_data=access_rule)

    print("Done!")
    logging.info("Complete!")
#----------------------------------------------------#