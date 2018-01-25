#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# UnapprovedDNS.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 1.0
# Release Date: 03/28/2017
#
# Summary
# -------
#
# This script quries the Stealthwatch SMC for bi-directional DNS flows to unapproved servers.
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
# How To Run
# ----------
#
#   1) Configure StealthWatch SW_DOMAIN_ID, SW_SMC_IP, SW_USERNAME, SW_PASSWORD
#   2) Configure the APPROVED_HOST_GROUP_IDS based on which Host Group contains approved DNS servers
#	3) Configure the QUERY_DURATION to get the most recent X number of seconds
#   4) Run the script / set a cron job
#
############################################################


####################
#  CONFIGURATION   #
####################
#
#----------------------------------------------------#
#

# StealthWatch SMC Variables
SW_DOMAIN_ID = "123"
SW_SMC_IP    = "192.168.1.1"
SW_USERNAME  = "admin"
SW_PASSWORD  = "lan411cope"

# StealthWatch Parent Host Group ID
APPROVED_HOST_GROUP_IDS = ['47', '27']

# Flow Query Duration (last X seconds)
QUERY_DURATION = 3600000

#
#----------------------------------------------------#

####################
# !!! DO WORK !!!  #
####################

import requests
import urllib
import xml.etree.ElementTree

from requests.auth import HTTPBasicAuth

# If receiving SSL Certificate Errors, un-comment the line below
requests.packages.urllib3.disable_warnings()

#----------------------------------------------------#
# A function to build getFlows XML for the SMC
def getFlowsXML(duration):
	global SW_DOMAIN_ID

	return_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	return_xml += "<soapenc:Envelope xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
	return_xml += "\t<soapenc:Body>\n"
	return_xml += "\t\t<getFlows>\n"
	return_xml += "\t\t\t<flow-filter max-rows=\"10000\" domain-id=\"{}\" remove-duplicates=\"true\" order-by=\"TOTAL_BYTES\" include-interface-data=\"false\">\n".format(SW_DOMAIN_ID)
	return_xml += "\t\t\t\t<date-selection>\n"
	return_xml += "\t\t\t\t\t<time-window-selection duration=\"{}\"/>\n".format(duration)
	return_xml += "\t\t\t\t</date-selection>\n"
	return_xml += "\t\t\t\t<host-selection>\n"
	return_xml += "\t\t\t\t\t<host-pair-selection direction=\"BETWEEN_SELECTION_1_SELECTION_2\">\n"
	return_xml += "\t\t\t\t\t\t<selection-1>\n"
	return_xml += "\t\t\t\t\t\t\t<host-group-selection host-group-id=\"{}\" />\n".format(1)
	return_xml += "\t\t\t\t\t\t</selection-1>\n"
	return_xml += "\t\t\t\t\t</host-pair-selection>\n"
	return_xml += "\t\t\t\t</host-selection>\n"
	return_xml += "\t\t\t\t<ports exclude=\"false\">53/udp</ports>\n"
	return_xml += "\t\t\t\t<traffic>\n"
	return_xml += "\t\t\t\t\t<client>\n"
	return_xml += "\t\t\t\t\t\t<packets-range low-value=\"1\" />\n"
	return_xml += "\t\t\t\t\t</client>\n"
	return_xml += "\t\t\t\t\t<server>\n"
	return_xml += "\t\t\t\t\t\t<packets-range low-value=\"1\" />\n"
	return_xml += "\t\t\t\t\t</server>\n"
	return_xml += "\t\t\t\t</traffic>\n"
	return_xml += "\t\t\t</flow-filter>\n"
	return_xml += "\t\t</getFlows>\n"
	return_xml += "\t</soapenc:Body>\n"
	return_xml += "</soapenc:Envelope>"

	return return_xml
#----------------------------------------------------#

#----------------------------------------------------#
# A function to post supplied XML to the SMC
def submitXMLToSMC(xml):
	global SW_SMC_IP, SW_USERNAME, SW_PASSWORD

	# Build the SMC URL
	SMC_URL = "https://{}/smc/swsService/flows".format(SW_SMC_IP)

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
			return http_req.text
		else:
			print 'SMC Connection Failure - HTTP Return Code: {}\nResponse: {}'.format(http_req.status_code, http_req.json())
			exit()

	except Exception as err:
		print 'Unable to post to the SMC - Error: {}'.format(err)
		exit()
#----------------------------------------------------#

# Get DNS flows from the SMC
dns_flows_xml = submitXMLToSMC(getFlowsXML(QUERY_DURATION))

# Parse the Host Group XML settings
root = xml.etree.ElementTree.fromstring(dns_flows_xml.encode('ascii', 'ignore'))

# iterate through all flows
for flow in root.findall('.//{http://www.lancope.com/sws/sws-service}flow'):
	
	# Get the client and server elements for the flow
	client = flow.find('.//{http://www.lancope.com/sws/sws-service}client')
	server = flow.find('.//{http://www.lancope.com/sws/sws-service}server')

	# Get the host groups of the server
	host_groups = server.get('host-group-ids').split(',')

	# Get any intersection of Host Groups
	host_groups = set(host_groups).intersection(APPROVED_HOST_GROUP_IDS)

	# If the DNS Server isn't in an approved Host Group, then print
	if len(host_groups) == 0:
		print 'Client: ' + client.get('ip-address') + '\t Server: ' + server.get('ip-address') + "\t Host Groups: " + server.get('host-group-ids')