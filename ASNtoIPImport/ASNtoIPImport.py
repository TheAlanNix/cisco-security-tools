#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# ASNtoIPImport.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 1.3
# Release Date: 3/21/2017
#
# Summary
# -------
#
# This script allows you to import IP ranges for common ASNs into StealthWatch Host Groups
# 
# Version 1.1: Now automatically adds/updates Host Groups based on whether they exist
# Version 1.2: Added the ability to have multiple search terms per Host Group
# Version 1.3: MaxMind changed the format of their zip file, so updated the unzip code
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
#   2) Configure the PARENT_HOST_GROUP_ID based on where you want groups to be imported
#   3) Configure ORG_HOSTGROUPS array for the appropriate search strings
#   4) Run the script / set a cron job
#
############################################################


####################
#  CONFIGURATION   #
####################
#
#----------------------------------------------------#
#

# Build file references
FILE_URL = "http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum2.zip"
FILE_ZIP = "GeoIPASNum2.zip"

# StealthWatch SMC Variables
SW_DOMAIN_ID = "123"
SW_SMC_IP    = "127.0.0.1"
SW_USERNAME  = "admin"
SW_PASSWORD  = "lan411cope"

# StealthWatch Parent Host Group ID
PARENT_HOST_GROUP_ID = 50000

# Set Host Group names and the associated search keywords
ORG_HOSTGROUPS = {
    "Akamai":       ["akamai"],
    "Amazon":       ["amazon.com"],
    "Apple":        ["AS6185 ", "AS714 "],
    "Cisco":        ["cisco systems"],
    "Dropbox":      ["dropbox"],
    "EdgeCast":     ["AS14153 ", "AS15133 "],
    "Facebook":     ["facebook"],
    "Google":       ["google"],
    "Hulu":         ["AS23286 "],
    "LinkedIn":     ["linkedin"],
    "Microsoft":    ["microsoft"],
    "Netflix":      ["netflix"],
    "Pandora":      ["pandora"],
    "Spotify":      ["spotify"],
    "Twitter":      ["twitter"],
    "Yahoo":        ["yahoo"],
    "WebEx":        ["webex"],
}

#
#----------------------------------------------------#


####################
# !!! DO WORK !!!  #
####################

import csv
import os
import requests
import urllib
import xml.etree.ElementTree
import zipfile

from requests.auth import HTTPBasicAuth

# If receiving SSL Certificate Errors, un-comment the line below
#requests.packages.urllib3.disable_warnings()

#----------------------------------------------------#
# A function to take MaxMind's IP format and make it readable.
def int2ip(addr):

    addr = int(addr)

    o1 = int((addr / 16777216) % 256)
    o2 = int((addr / 65536   ) % 256)
    o3 = int((addr / 256     ) % 256)
    o4 = int((addr           ) % 256)
 
    return str(o1) + "." + str(o2) + "." + str(o3) + "." + str(o4)
#----------------------------------------------------#

#----------------------------------------------------#
# A function to build getHostGroups XML for the SMC
def getHostGroupsXML():

    return_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    return_xml += "<soapenc:Envelope xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
    return_xml += "\t<soapenc:Body>\n"
    return_xml += "\t\t<getHostGroups>\n"
    return_xml += "\t\t\t<domain id=\"{}\" />\n".format(SW_DOMAIN_ID)
    return_xml += "\t\t</getHostGroups>\n"
    return_xml += "\t</soapenc:Body>\n"
    return_xml += "</soapenc:Envelope>"

    return return_xml
#----------------------------------------------------#

#----------------------------------------------------#
# A function to build addHostGroup XML for the SMC
def addHostGroupXML(ip_array, org_name):

    return_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    return_xml += "<soapenc:Envelope xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
    return_xml += "\t<soapenc:Body>\n"
    return_xml += "\t\t<addHostGroup>\n"
    return_xml += "\t\t\t<host-group domain-id=\"{}\" name=\"{}\" parent-id=\"{}\">\n".format(SW_DOMAIN_ID, org_name, PARENT_HOST_GROUP_ID)

    for ip_address in ip_array:
        return_xml += "\t\t\t\t<ip-address-ranges>{}</ip-address-ranges>\n".format(ip_address)
    
    return_xml += "\t\t\t</host-group>\n"
    return_xml += "\t\t</addHostGroup>\n"
    return_xml += "\t</soapenc:Body>\n"
    return_xml += "</soapenc:Envelope>"

    return return_xml
#----------------------------------------------------#

#----------------------------------------------------#
# A function to build setHostGroupIPRange XML for the SMC
def setHostGroupIPRangeXML(ip_array, group_id):

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

    # Build the SMC URL
    SMC_URL = "https://{}/smc/swsService/configuration".format(SW_SMC_IP)

    # Build HTTP Authentication Instance
    auth = HTTPBasicAuth(SW_USERNAME, SW_PASSWORD)

    print("Posting data to the SMC...")

    # Try to make the POST, else print the error
    try:
        # Make the POST request
        http_req = requests.post(url=SMC_URL, auth=auth, data=xml, verify=False)

        # Check to make sure the POST was successful
        if http_req.status_code == 200:
            print('Success.')
            return http_req.text
        else:
            print('SMC Connection Failure - HTTP Return Code: {}\nResponse: {}'.format(http_req.status_code, http_req.json()))
            exit()

    except Exception as err:
        print('Unable to post to the SMC - Error: {}'.format(err))
        exit()
#----------------------------------------------------#

#----------------------------------------------------#
if __name__ == "__main__":
    
    # Get the Host Groups from StealthWatch
    host_groups_xml = submitXMLToSMC(getHostGroupsXML())

    # Parse the Host Group XML settings
    root = xml.etree.ElementTree.fromstring(host_groups_xml.encode('ascii', 'ignore'))

    # Get the Parent Host Group that was specified
    parent_host_group = root.find('.//{http://www.lancope.com/sws/sws-service}host-group[@id="' + str(PARENT_HOST_GROUP_ID) + '"]')

    print("Fetching new ASN data from MaxMind...")

    # Get the IP-to-ASN database from MaxMind
    maxmind_file = requests.get(FILE_URL, allow_redirects=True)
    open(FILE_ZIP, 'wb').write(maxmind_file.content)

    print("Unzipping downloaded file...")

    # Unzip the file from MaxMind
    with zipfile.ZipFile(FILE_ZIP, "r") as z:
        file_name = z.namelist()
        file_name = file_name[0]
        z.extract(file_name)

    file_name = './' + file_name

    print("Opening CSV...")

    # Open the CSV file and parse it
    with open(file_name, "r", encoding="ISO-8859-1") as csvfile:
        
        # Set up the CSV Reader
        csv_reader = csv.reader(csvfile)

        # Go through each "org" entry 
        for org, keywords in ORG_HOSTGROUPS.items():

            # Create a Host Group placeholder
            host_group_id = 0

            # Create and IP array for this Org
            ip_array = []

            print("Getting IP ranges for " + org + "...")

            # Go through each keyword for the Host Group
            for keyword in keywords:

                # Reset back to the beginning of the CSV
                csvfile.seek(0)

                # Go through each row of the CSV
                for row in csv_reader:
                    
                    # If the keyword is in the description, then add it to our array
                    if keyword.lower() in row[2].lower():

                        # Add the IP range to our array
                        ip_array.append(int2ip(row[0]) + "-" + int2ip(row[1]))

                        # Print details about the find
                        print("Found IP range " + str(int2ip(row[0]) + "-" + int2ip(row[1])).ljust(30) + " for " + org + " with keyword " + keyword + " in " + row[2])
            
            # If the length of the ip_array is more than one, then post the data to the SMC
            if len(ip_array) > 0:

                try: 
                    # Iterate through all the of the children of the parent Host Group to see if it's the one we need
                    for child_host_group in parent_host_group.findall('.//{http://www.lancope.com/sws/sws-service}host-group'):
                        
                        # If the Host Group name matches the Org, then use it
                        if org.lower() in child_host_group.get('name').lower():
                            host_group_id = child_host_group.get('id')
                except:
                    print('\033[1;31mUnable to locate either the Domain ID or Host Group ID - Please check the config section of the script.\033[1;m')
                    exit()

                # If the Host Group didn't exist, make a new one, otherwise, just update
                if host_group_id is 0:
                    print("Submitting XML to the SMC for " + org + " and creating a new group")
                    submitXMLToSMC(addHostGroupXML(ip_array, org))
                else:
                    print("Submitting XML to the SMC for " + org + " and Group ID " + str(host_group_id))
                    submitXMLToSMC(setHostGroupIPRangeXML(ip_array, host_group_id))
            else:
                # Print that we didn't find any data
                print("No IP Ranges were found for the Org " + org + "...")

    # Clean up the downloaded/extracted files
    os.remove(file_name)
    os.remove(FILE_ZIP)
#----------------------------------------------------#