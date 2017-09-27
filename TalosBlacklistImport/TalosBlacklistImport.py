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
# Version: 1.0
# Release Date: 4/28/2016
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
#     - python get-pip.py		(may need to use 'sudo')
#     - pip install requests	(may need to use 'sudo')
#
#
# How To Run
# ----------
#
#   1) Configure StealthWatch SW_DOMAIN_ID, SW_SMC_IP, SW_USERNAME, SW_PASSWORD
#   2) Configure HOSTGROUP_ID where you want the list imported
#   3) Run the script / set a cron job
#
############################################################



####################
#  CONFIGURATION   #
####################
#
#----------------------------------------------------#
#

# Build file references
LIST_URL = "http://www.talosintel.com/feeds/ip-filter.blf"

# StealthWatch SMC Variables
SW_DOMAIN_ID = "123"
SW_SMC_IP    = "127.0.0.1"
SW_USERNAME  = "admin"
SW_PASSWORD  = "lan411cope"

# Talos Host Group ID
HOSTGROUP_ID = 85

#
#----------------------------------------------------#


####################
# !!! DO WORK !!!  #
####################

import json
import requests
import urllib

from requests.auth import HTTPBasicAuth
requests.packages.urllib3.disable_warnings()

# A function to build setHostGroupIPRange XML for the SMC
def setHostGroupIPRangeXML(ip_array, group_id):
	global SW_DOMAIN_ID

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

# A function to post supplied XML to the SMC
def submitXMLToSMC(xml):
	global SW_SMC_IP, SW_USERNAME, SW_PASSWORD

	# Build the SMC URL
	SMC_URL = "https://{}/smc/swsService/configuration".format(SW_SMC_IP)

	# Build HTTP Authentication Instance
	auth = HTTPBasicAuth(SW_USERNAME, SW_PASSWORD)

	print "Posting data to the SMC..."

	# Try to make the POST, else print the error
	try:
		# Make the POST request
		http_req = requests.post(url=SMC_URL, auth=auth, data=xml, verify=False)

		# Check to make sure the POST was successful
		if http_req.status_code >= 200 and http_req.status_code < 300:
			print 'Success.'
		else:
			print 'SMC Connection Failure - HTTP Return Code: {}\nResponse: {}'.format(http_req.status_code, http_req.json())
			exit()

	except Exception as err:
		print 'Unable to post to the SMC - Error: {}'.format(err)
		exit()

# Execute commands to get the threat feed and then import it
if __name__ == "__main__":
	
	# Create an IP array
	ip_array = []

	print "Fetching new IP data from Talos..."

	# Get the IP data from Talos
	response = requests.get(LIST_URL, stream=True)

	# Add each IP address to our ip_array
	for line in response.iter_lines():
	    if line:
	    	ip_array.append(line)

	# Make the XML and submit to the SMC
	submitXMLToSMC(setHostGroupIPRangeXML(ip_array, HOSTGROUP_ID))
