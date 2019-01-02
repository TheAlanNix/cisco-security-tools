# Cisco Security Tools

This is a simple repository for scripts that I've written over the years to automate or simplify operations with Cisco Security products.

Most scripts were written to handle specific use cases, but hopefully they can be used as sample/example code.

I'm in the process of documenting the scripts and updating them for Python 3.x. The scripts referenced in this document have been updated.

## [AMPLookup](AMPLookup/)

This is a simple PHP script to look up the UUID of an AMP for Endpoints client based on a given IP address.  The script then redirects to the device trajectory of that client.

This was built to provide a pivot into the AMP console for other solutions that were only capable of providing an IP address.

## [AnomaliImporter](AnomaliImporter/)

This is a script to take in various threat intelligence feeds from Anomali (formerly ThreatStream) and import the pertinent IP address data into Stealthwatch.

Stealtwatch could then have Custom Security Events to monitor and alarm for traffic to those IPs.

## [ASNtoIPImport](ASNtoIPImport/)

This is a script to import IP subnets that are advertised by specific ASNs into Stealthwatch host groups.

The ASN to IP mapping data is sourced from MaxMind.  The script will search through their data for specified keywords, and then add the associated IP ranges to a Stealthwatch host group of the specified name.

## [CheckpointObjectImport](CheckpointObjectImport/)

This set of scripts was created to migrate Checkpoint objects to a Firepower Management Console.  These were built to aid customers in migrating from Checkpoint to Firepower.

The *CP-to-FMC-Network-Object-Import* file will migrate network objects from the Checkpoint SmartConsole

The *CP-to-FMC-Service-Object-Import* file will migrate service/port objects from the Checkpoint SmartConsole

**TODO**: Nested objects (Objects of Objects) need some work.  Currenty the scripts only import one level.

**PLEASE BE CAREFUL WITH THIS ONE**  
The *NetworkObjectDelete* file will remove all objects from the FMC which have a specified prefix.  Please make sure you specify a prefix, or you **WILL** delete all objects.  "BOGUS_PREFIX" is now the default to prevent accidents.

## [FirepowerEnableLogging](FirepowerEnableLogging/)

This script will go through all of the rules in a Firepower 6.3 Access Control policy and enable logging.  You'll first want to make a copy of the target policy in the FMC UI, then select that policy when prompted by the script.

Currently, I haven't found a way to update the "Default Action" log settings, so that's still manual, but this should handle all other rules.

Also, there's no bulk update (only insert) for the access control rules, so this puppy can take a while if you have a lot of rules.

## [FirepowerImportScripts](FirepowerImportScripts/)

These scripts are meant to be very basic examples of how to import Hosts / URLs from a CSV, into an object in the Firepower Management Center.

## [FirepowerLogstash](FirepowerLogstash/)

This is a simple Logstash configuration for the Firepower Syslog format.  This config should work with 6.2.3 and prior, and it should also now support the new syslog format for FTD 6.3

## [FirepowerPolicyToCSV](FirepowerPolicyToCSV/)

This script will export an Access Control Policy from the FMC into a CSV file.  Just run the script, and you'll get prompted for the FMC IP/Username/Password.  The script will connect to the FMC, then list all of the Access Control policies and allow you to pick which one you want to export.

## [ISEPortalTweaks](ISEPortalTweaks/)

This is a collection of files that can be used to augment the behavior of portals within ISE.

## [StealthwatchExporterUpdate](StealthwatchExporterUpdate/)

This is a collection of scripts that can be used to manipulate exporters in Stealthwatch.  The *getExporters* script will grab all exporter IPs from Stealthwatch, and export them to a CSV file.  The *bulkDeleteExporters* script is meant to be used when cleaning up decomissioned routers/firewalls/switches - it will remove all exporters (sans FlowSensors) that are not explicitly defined in a whitelist.

These are decent examples of how to leverage the REST API code within Stealthwatch.

## [TalosBlacklistImport](TalosBlacklistImport/)

This is a script to import the Talos IP Blacklist into a specific host group within Stealthwatch.  This would also allow you to also set a Custom Security Event for any traffic to/from IPs within that host group.