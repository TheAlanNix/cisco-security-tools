#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# Office365Importer.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 1.0
# Release Date: 9/15/2016
#
# Summary
# -------
#
# This script imports all of the IPv4 and IPv6 ranges for Office 365 products
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
#   2) Configure the HOST_GROUP_ID based on where you want groups to be imported
#   3) Run the script / set a cron job
#
############################################################


####################
#  CONFIGURATION   #
####################
#
#----------------------------------------------------#
#

# Where do get the XML data from Microsoft
O365_XML_URL = "https://support.content.office.net/en-us/static/O365IPAddresses.xml"

# StealthWatch SMC Variables
SW_DOMAIN_ID = "123"
SW_SMC_IP    = "127.0.0.1"
SW_USERNAME  = "admin"
SW_PASSWORD  = "lan411cope"

# StealthWatch Office 365 Host Group ID
HOST_GROUP_ID = 50000

#
#----------------------------------------------------#

####################
# !!! DO WORK !!!  #
####################

import requests
import urllib
import xml.etree.ElementTree

from requests.auth import HTTPBasicAuth
requests.packages.urllib3.disable_warnings()

#----------------------------------------------------#
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
#----------------------------------------------------#

#----------------------------------------------------#
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
		if http_req.status_code == 200:
			print 'Success.'
			return http_req.text
		else:
			print 'SMC Connection Failure - HTTP Return Code: {}\nResponse: {}'.format(http_req.status_code, http_req.json())
			exit()

	except Exception as err:
		print 'Unable to post to the SMC - Error: {}'.format(err)
		exit()
#----------------------------------------------------#

# Placeholder array for Office 365 IPs
ip_array = []

# Get the Office 365 XML
O365_XML = urllib.urlopen(O365_XML_URL).read()

# Parse the Office 365 XML
root = xml.etree.ElementTree.fromstring(O365_XML.encode('ascii', 'ignore'))

# Get the IPv4 addresses for the product
v4_address_lists = root.findall('.//addresslist[@type="IPv4"]')

# If there aren't any IPv4 addresses then skip
for v4_address_list in v4_address_lists:

	# Get all of the v4 address ranges
	v4_addresses = v4_address_list.findall('address')

	# Add each IP range to our array
	for v4_address in v4_addresses:

		# Add the IP range to our array
		ip_array.append(v4_address.text)

# Get the IPv6 address for the product
v6_address_lists = root.findall('.//addresslist[@type="IPv6"]')

# If there aren't any IPv6 addresses then skip
for v6_address_list in v6_address_lists:
	
	# Get all of the v6 address ranges
	v6_addresses = v6_address_list.findall('address')
	
	# Add each IP range to our array
	for v6_address in v6_addresses:
		
		# Add the IP range to our array
		ip_array.append(v6_address.text)

# Submit the data to the SMC
print submitXMLToSMC(setHostGroupIPRangeXML(ip_array, HOST_GROUP_ID))
