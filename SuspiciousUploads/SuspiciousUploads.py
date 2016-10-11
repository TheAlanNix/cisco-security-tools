#!/usr/bin/env python
#  -*- coding: utf-8 -*-

#####################
# ABOUT THIS SCRIPT #
#####################
#
# SuspiciousUploads.py
# ----------------
# Author: Alan Nix
# Property of: Cisco Systems
# Version: 1.0
# Release Date: 10/11/2016
#
# Summary
# -------
#
# This script will run custom queries on the FlowCollector to retrieve suspicious uploads to external subnets with a low peer count, and then email the results.
# 
#
# Requirements
# ------------
#
#	1) Must have Python installed.
#
#
# How To Run
# ----------
#
#	1) Configure Email variables EMAIL_RELAY, EMAIL_FROM, EMAIL_TO
#	2) Configure the Byte/Subnet Peer limits to tune out noise
#	3) Configure a "trusted" Host Group to allow for tuning
#	4) Run the script / set a cron job
#
############################################################


####################
#  CONFIGURATION   #
####################
#
#----------------------------------------------------#
#

# Email Variables
EMAIL_RELAY	= "smtp.example.com"
EMAIL_FROM	= "stealthwatch@example.com"
EMAIL_TO	= ["john.doe@example.com", "jane.doe@example.com"]

# Tuning Variables
EXFIL_BYTE_COUNT = 10000000
EXFIL_PEER_COUNT = 5
SUBNET_GROUPING_NETMASK = "255.255.255.0"
TRUSTED_HOST_GROUP = 47

# Timeframe Variables
CURRENT_TIME	= datetime.datetime.utcnow()
START_TIME		= datetime.datetime.utcnow() - datetime.timedelta(days = 1)
PEER_COUNT_TIME	= datetime.datetime.utcnow() - datetime.timedelta(days = 30)

#
#----------------------------------------------------#


####################
# !!! DO WORK !!!  #
####################

import datetime
import os
import smtplib
import subprocess

#----------------------------------------------------#
# A function to run a remote command on the FlowCollector
def runCommands(commands):

	# Iterate through all commands sequentially
	for command in commands:

		# Run the command, and return the output
		command_output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE).stdout.read()

	# Return the stdout from the commands
	return command_output
#----------------------------------------------------#

#----------------------------------------------------#
# A function to run a database query on a FlowCollector
def runQuery(query):

	# Build the command string that we need to run
	query_string = "/opt/vertica/bin/vsql -U dbadmin -w lan1cope -c "
	query_string += "\"" + query + "\"";

	# Run the command remotely
	stdout = runCommands([query_string])

	return stdout
#----------------------------------------------------#

#----------------------------------------------------#
# Runs a query to look for internal clients sending data to external servers over a specified byte count with a low number of peers
def makeSuspiciousExfiltrationQuery():
	
	global CURRENT_TIME, START_TIME, PEER_COUNT_TIME, EXFIL_BYTE_COUNT, EXFIL_PEER_COUNT, TRUSTED_HOST_GROUP, SUBNET_GROUPING_NETMASK

	print "Searching for clients that have uploaded more than {} bytes to new unique external hosts...".format(EXFIL_BYTE_COUNT)

	query_string = """SELECT * FROM
	(SELECT * FROM 
		(SELECT
			id,
			V6_NTOA(MIN(client_ip_address)) AS client_ip,
			V6_NTOA(MIN(server_ip_address)) AS server_ip,
			SUM(client_bytes) AS client_bytes,
			SUM(client_bytes + server_bytes) AS total_bytes,
			SUM(client_bytes)/SUM(client_bytes + server_bytes)*100 AS client_percentage
		FROM flow_stats
		WHERE last_time >= '{}'
			AND last_time < '{}'
			AND ((client_group_list LIKE '%,'||'1'||',%')
				AND ((server_group_list LIKE '%,'||'0'||',%')
					AND (server_group_list NOT LIKE '%,'||'{}'||',%')))
		GROUP BY id
		ORDER BY SUM(client_bytes) DESC) AS client_orientation
	WHERE client_percentage > 60
		AND client_bytes > {}
	ORDER BY total_bytes DESC) AS uploads_to_outside
JOIN
	(SELECT * FROM
		(SELECT *  FROM
			(SELECT
				MIN(start_time) as server_first_seen,
				V6_NTOA(server_ip_address) AS server_ip,
				V6_NTOA(server_ip_address & V6_ATON('{}')) AS server_subnet,
				COUNT(DISTINCT client_ip_address) AS peer_count
			FROM flow_stats
			WHERE (server_group_list LIKE '%,'||'0'||',%')
			GROUP BY server_ip_address) AS first_seen_list
		JOIN
			(SELECT
				V6_NTOA(server_ip_address & V6_ATON('{}')) AS server_subnet,
				COUNT(DISTINCT client_ip_address) AS subnet_peer_count
			FROM flow_stats
			WHERE (server_group_list LIKE '%,'||'0'||',%')
				AND last_time >= '{}'
				AND last_time < '{}'
			GROUP BY server_subnet) AS subnet_peer_list
		ON first_seen_list.server_subnet = subnet_peer_list.server_subnet) AS subnet_peer_table
	WHERE server_first_seen >= '{}'
	AND subnet_peer_count <= {}
	ORDER BY subnet_peer_count, server_first_seen ASC) AS recent_low_peer_subnets
ON recent_low_peer_subnets.server_ip = uploads_to_outside.server_ip""".format(START_TIME, CURRENT_TIME, TRUSTED_HOST_GROUP, EXFIL_BYTE_COUNT, SUBNET_GROUPING_NETMASK, SUBNET_GROUPING_NETMASK, PEER_COUNT_TIME, CURRENT_TIME, START_TIME, EXFIL_PEER_COUNT)

	return query_string
#----------------------------------------------------#

query_results = runQuery(makeSuspiciousExfiltrationQuery())

# If no query results were returned, then exit
if "(0 rows)" in query_results:
	exit()

# Build an email with the query results
email_message = """\
From: {}
To: {}
Subject: Suspicious Uploads Report from StealthWatch - {}

{}
""".format(EMAIL_FROM, EMAIL_TO, CURRENT_TIME, query_results)

# Send the results of the query
email_server = smtplib.SMTP(EMAIL_RELAY)
email_server.sendmail(EMAIL_FROM, EMAIL_TO, email_message)
email_server.quit()