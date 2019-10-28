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
# Version: 1.1
# Release Date: 02/23/2019
#
# Summary
# -------
#
# This script will connect to the Firepower Management Center and then enable logging on all rules in a selected access policy.
# Currently this only works with Firepower 6.3.
#
# Version 1.1:
#   - Added logic to check to see if all logging is already enabled.
#   - Attempt to automatically renew the auth token if a 401 is recieved from the FMC.
#   - Converted script to PEP-8 formatting.
#
# Requirements
# ------------
#
#   1) Must have Python 3.x installed.
#   2) Must have 'requests' Python module installed.
#       You'll probably want to set up a virtual environment (https://docs.python.org/3/tutorial/venv.html)
#     - wget https://bootstrap.pypa.io/get-pip.py
#     - python get-pip.py       (may need to use 'sudo')
#     - pip install requests    (may need to use 'sudo')
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

from requests.packages import urllib3
from requests.auth import HTTPBasicAuth

# If receiving SSL Certificate Errors, un-comment the line below
urllib3.disable_warnings()

####################
#  CONFIGURATION   #
####################
#
# ---------------------------------------------------- #
#

# Logging Parameters
logging.basicConfig(filename='FirepowerEnableLogging.log', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filemode='w', level=logging.INFO)

# Firepower Management Console Variables
FMC_IP = ""
FMC_USERNAME = None
FMC_PASSWORD = None
FMC_DOMAIN_UUID = None

#
# ---------------------------------------------------- #

#################
#    GLOBALS    #
#################

FMC_AUTH_TOKEN = None
FMC_REFRESH_TOKEN = None

###################
#    FUNCTIONS    #
###################


def get_auth_token():
    '''A function to get an authentication token from the FMC'''

    global FMC_AUTH_TOKEN, FMC_REFRESH_TOKEN, FMC_DOMAIN_UUID

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

        # Store the refresh token
        FMC_REFRESH_TOKEN = http_req.headers.get('X-auth-refresh-token', default=None)

        # Let the user pick the domain
        domain_data = json.loads(http_req.headers.get('DOMAINS', default=None))
        FMC_DOMAIN_UUID = process_domains(domain_data)

        # If we didn't get a token, then something went wrong
        if FMC_AUTH_TOKEN is None:
            print('Authentication Token Not Found...')
            logging.error('Authentication Token Not Found. Exiting...')
            exit()

        logging.info('Authentication Token Successfully Fetched.')
        logging.debug('Auth Token: {}'.format(FMC_AUTH_TOKEN))

    except Exception as err:
        print('Error fetching auth token from FMC: {}'.format(err))
        logging.error('Error fetching auth token from FMC: {}'.format(err))
        exit()


def refresh_auth_token():
    '''A function to refresh the FMC auth token'''

    global FMC_AUTH_TOKEN, FMC_REFRESH_TOKEN

    logging.info('Refreshing Authentication Token from FMC...')

    # Build HTTP Headers
    auth_headers = {'Content-Type': 'application/json', 'X-auth-access-token': FMC_AUTH_TOKEN, 'X-auth-refresh-token': FMC_REFRESH_TOKEN}

    # Build URL for token refresh
    auth_url = "https://{}/api/fmc_platform/v1/auth/refreshtoken".format(FMC_IP)

    try:
        http_req = requests.post(url=auth_url, headers=auth_headers, verify=False)

        logging.debug('FMC Auth Response:\n{}'.format(http_req.headers))

        # Store the auth token
        FMC_AUTH_TOKEN = http_req.headers.get('X-auth-access-token', default=None)

        # Store the refresh token
        FMC_REFRESH_TOKEN = http_req.headers.get('X-auth-refresh-token', default=None)

        # If we didn't get a token, then something went wrong
        if FMC_AUTH_TOKEN is None:
            print('Authentication Token Not Found. This likely means we\'ve refreshed three times, a hard limit on the FMC.')
            logging.error('Authentication Token Not Found. This likely means we\'ve refreshed three times, a hard limit on the FMC. Exiting...')
            exit()

        logging.info('Authentication Token Successfully Refreshed.')
        logging.debug('Auth Token: {}'.format(FMC_AUTH_TOKEN))

    except Exception as err:
        print('Error refreshing auth token from FMC: {}'.format(err))
        logging.error('Error refreshing auth token from FMC: {}'.format(err))
        exit()


def process_domains(domain_list):
    '''A function to parse the domains returned by the FMC'''

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


def call_fmc_api(method, endpoint, json_data=None, retry=3):
    '''A function to call the FMC API'''

    # If there's no FMC Authentication Token, then fetch one
    if FMC_AUTH_TOKEN is None:
        get_auth_token()

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
        elif http_req.status_code == 401:

            # Decrement retries
            retry -= 1

            # If we've hit the retry limit, bail
            if retry == 0:
                print('Error refreshing auth token from FMC. Retry limit exceeded.')
                logging.error('Error refreshing auth token from FMC. Retry limit exceeded.')
                exit()

            # Attempt to refresh the auth token
            refresh_auth_token()

            # Retry the current API call
            call_fmc_api(method, endpoint, json_data, retry=retry)
        else:
            print("FMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(http_req.status_code, http_req.json()))
            logging.error("FMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(http_req.status_code, http_req.json()))
            exit()

    except Exception as err:
        print('Error posting request to FMC: {}'.format(err))
        logging.error('Error posting request to FMC: {}'.format(err))
        exit()


def call_fmc_api_paginated(endpoint):
    '''A function to call the FMC API and get all paginated results'''

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
        fmc_response = call_fmc_api('GET', paginated_url)

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


###################
# !!! DO WORK !!! #
###################


if __name__ == "__main__":
    '''Enable logging on all rules within an Access Control Policy'''

    # If not hard coded, get the FMC IP, Username and Password
    if not FMC_IP:
        FMC_IP = input("FMC IP Address: ")
    if FMC_USERNAME is None:
        FMC_USERNAME = input("FMC Username: ")
    if FMC_PASSWORD is None:
        FMC_PASSWORD = getpass.getpass("FMC Password: ")

    # Fetch all policies from the FMC
    access_policies = call_fmc_api_paginated('policy/accesspolicies')

    print("\nPlease select which access policy you'd like to modify:\n")

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
        print("ERROR: Policy selection was not valid.")
        exit()

    print("Working...")

    # ######## TODO #########
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
    access_policy_rules = call_fmc_api_paginated('policy/accesspolicies/{}/accessrules'.format(access_policies[selected_policy]["id"]))

    # Iterate through all rules and enable logging
    for access_rule in access_policy_rules:

        print("Checking Rule '{}'...".format(access_rule["name"]))

        # Check to see if all logging is already enabled
        if access_rule["enableSyslog"] and access_rule["logBegin"] and access_rule["logEnd"] and access_rule["sendEventsToFMC"]:
            print('All logging already enabled for this rule... skipping.')
            continue

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

        print('Enabling logging...')

        call_fmc_api('PUT', 'policy/accesspolicies/{}/accessrules/{}'.format(access_policies[selected_policy]["id"], access_rule["id"]), json_data=access_rule)

    print("Done!")
    logging.info("Complete!")
