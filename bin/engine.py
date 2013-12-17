#
# SNMP Engine for Splunk
#
#
#
#
import os
import sys
from collections import defaultdict
import netsnmp
import json
import ConfigParser 
import time 

SPLUNK_HOME = '/opt/splunk'
DEVICES_CONF = 'local/switches.conf'
SNMP_CONF = 'local/snmp.conf'

#
# Get the current timestamp 
#
def timestamp(): 

	# Return timestamp
	return time.asctime(time.localtime(time.time()))
	
	
#
# Write event to stdout to be captured by Splunk
# 
def writeEvent(str): 

	print(timestamp() + ' - SNMP: ' + str) 
	
	return 


def main():
 
    os.chdir(SPLUNK_HOME + '/etc/apps/TA-snmpcollector/') 
    # Process the configuration
    (snmpcmd) = process_conf()

    with open(DEVICES_CONF, 'r') as devices: 
	
	for line in devices:
			
		snmpcmd['ipaddress'] = line
			
		# Get sysID
		device_oid_id = get_sys_object_id(snmpcmd)
 
		# Stop completely before creating new files if SNMP
		# isn't working
		if not device_oid_id:
			writeEvent("logtype=status, hostname=,ipaddr="+line)
			continue
				
		do_poll(snmpcmd)
			
 
 
def is_number(val):
    """Check if argument is a number
 
    Args:
        val: String to check
 
    Returns:
        True if a number
    """
 
    try:
        float(val)
        return True
    except ValueError:
        return False
 
def get_oid_last_octet(oid):
    """Get the last octet of OID
 
    Args:
        oid: OID to check
 
    Returns:
        Last octet
    """
 
    octets = oid.split('.')
    return octets[-1]
 
def do_snmpwalk(snmpcmd, oid_to_get):
    """Do an SNMPwalk
 
    Args:
        snmpcmd: SNMP variables required to do SNMP queries on device
        oid_to_get: OID to walk
 
    Returns:
        Dictionary of tuples (OID, value)
    """
 
    return do_snmpquery(snmpcmd, oid_to_get, False)
 
def do_snmpget(snmpcmd, oid_to_get):
    """Do an SNMPget
 
    Args:
        snmpcmd: SNMP variables required to do SNMP queries on device
        oid_to_get: OID to walk
 
    Returns:
        Dictionary of tuples (OID, value)
    """
 
    return do_snmpquery(snmpcmd, oid_to_get, True)
 
def do_snmpquery(snmpcmd, oid_to_get, snmpget):
    """Do an SNMP query
 
    Args:
        snmpcmd: SNMP variables required to do SNMP queries on device
        oid_to_get: OID to walk
        snmpget: Flag determining whether to do a GET or WALK
 
    Returns:
        Dictionary of tuples (OID, value)
    """
 
    # Initialize variables
    return_results = {}
    results_objs = False
    session = False
 
    # Get OID
    try:
        session = netsnmp.Session(DestHost=snmpcmd['ipaddress'],
            Version=snmpcmd['version'], Community=snmpcmd['community'],
            SecLevel='authPriv', AuthProto=snmpcmd['authprotocol'],
            AuthPass=snmpcmd['authpassword'], PrivProto=snmpcmd['privprotocol'],
            PrivPass=snmpcmd['privpassword'], SecName=snmpcmd['secname'],
            UseNumeric=True)
        results_objs = netsnmp.VarList(netsnmp.Varbind(oid_to_get))
 
        if snmpget:
            session.get(results_objs)
        else:
            session.walk(results_objs)
 
    except Exception as exception_error:
    # Check for errors and print out results
        print ('ERROR: Occurred during SNMPget for OID %s from %s: '
               '(%s)') % (oid_to_get, snmpcmd['ipaddress'], exception_error)
        sys.exit(2)
 
    # Crash on error
    if (session.ErrorStr):
        print ('ERROR: Occurred during SNMPget for OID %s from %s: '
               '(%s) ErrorNum: %s, ErrorInd: %s') % (
                oid_to_get, snmpcmd['ipaddress'], session.ErrorStr,
                session.ErrorNum, session.ErrorInd)
        sys.exit(2)
 
    # Construct the results to return
    for result in results_objs:
        if is_number(result.val):
            return_results[('%s.%s') % (result.tag, result.iid)] = (
                float(result.val))
        else:
            return_results[('%s.%s') % (result.tag, result.iid)] = (
                result.val)
 
    return return_results
 
def get_sys_object_id(snmpcmd):
    """Get the sysObjectID of the device
 
    Args:
        snmpcmd: SNMP variables required to do SNMP queries on device
 
    Returns:
        val: OID value
    """
 
    sysobjectid = '.1.3.6.1.2.1.1.2.0'
    snmp_results = do_snmpget(snmpcmd, sysobjectid)
    for val in snmp_results.values():
        return val
 
def do_poll(snmpcmd):

    ip = snmpcmd['ipaddress']

    # 
    # Poll System Status
    #

    # Get the system name of the device
    sysName_oid = '.1.3.6.1.2.1.1.5.0'
    sysName_results = do_snmpget(snmpcmd, sysName_oid)
    if sysName_results: 
    	for val in sysName_results.values():
		hostname = val 
		
	writeEvent("logtype=status, hostname="+hostname+", ipaddr="+ip+", status=up")
    else:
	writeEvent("logtype=status, hostname=,ipaddr="+ip+", status=down")

    
    #
    # Poll System Information
    #

    # Get the switch model
    model_oid = '.1.3.6.1.2.1.47.1.1.1.1.13.1001'
    model_results = do_snmpget(snmpcmd, model_oid)
    for val in model_results.values():
    	model = val

    # Get the serial
    serial_oid = '.1.3.6.1.2.1.47.1.1.1.1.11.1001'
    serial_results = do_snmpget(snmpcmd, serial_oid)
    for val in serial_results.values():
        serial = val

    # Get the Software
    software_oid = '.1.3.6.1.2.1.47.1.1.1.1.10.1001'
    software_results = do_snmpget(snmpcmd, software_oid)
    for val in software_results.values():
        software = val

    # Get the location
    location_oid = '.1.3.6.1.2.1.1.6.0'
    location_results = do_snmpget(snmpcmd, location_oid)
    for val in location_results.values():
        location = val    	

    # Dump system information
    writeEvent("logtype=sysinfo, hostname="+hostname+", ipaddr="+ip+", model="+model+", serial="+serial+", software="+software+", location="+location+",")


    #
    # System Performance
    #	
    # CPU USAGE
    cpu_5m_oid = '.1.3.6.1.4.1.9.2.1.58.0'
    cpu_1m_oid = '.1.3.6.1.4.1.9.2.1.57.0'
    cpu_5s_oid = '.1.3.6.1.4.1.9.2.1.56.0' 

    cpu_5m_results = do_snmpget(snmpcmd, cpu_5m_oid)
    for val in cpu_5m_results.values():
        cpu_5m = str(val)

    cpu_1m_results = do_snmpget(snmpcmd, cpu_1m_oid)
    for val in cpu_1m_results.values():
	cpu_1m = str(val)

    cpu_5s_results = do_snmpget(snmpcmd, cpu_5s_oid)
    for val in cpu_5s_results.values():
        cpu_5s = str(val)

    # MEMORY USAGE
    mem_free_oid = '.1.3.6.1.4.1.9.9.48.1.1.1.5.1'
    mem_used_oid = '.1.3.6.1.4.1.9.9.48.1.1.1.6.1'

    mem_free_results = do_snmpget(snmpcmd, mem_free_oid)
    mem_used_results = do_snmpget(snmpcmd, mem_used_oid)

    for val in mem_free_results.values():
	memfree = int(val)

    for val in mem_used_results.values():
	memused = int(val)

    memtotal = memfree + memused
    
    # Dump sysperf 
    writeEvent("logtype=sysperf, hostname="+hostname+", ipaddr="+ip+", cpu_5m="+cpu_5m+", cpu_1m="+cpu_1m+", cpu_5s="+cpu_5s+", memtotal="+str(memtotal)+", memused="+str(memused)+", memfree="+str(memfree))



    #
    # Poll Interfaces
    # 

    # Initialize variables
    ifmap = defaultdict(lambda: defaultdict(dict))
 
    # Description
    ifdesc_oid = '.1.3.6.1.2.1.31.1.1.1.18'
    ifdesc_results = do_snmpwalk(snmpcmd, ifdesc_oid)
    for oid, val in sorted(ifdesc_results.items()):
        last_octet = get_oid_last_octet(oid)
        ifmap[last_octet]['desc'] = val
 
    # Names
    ifname_oid = '.1.3.6.1.2.1.2.2.1.2'
    ifname_results = do_snmpwalk(snmpcmd, ifname_oid)
    for oid, val in sorted(ifname_results.items()):
        last_octet = get_oid_last_octet(oid)
        ifmap[last_octet]['name'] = val
 
    # Index
    ifindex_oid = '.1.3.6.1.2.1.2.2.1.1'
    ifindex_results = do_snmpwalk(snmpcmd, ifindex_oid)
    for oid, val in sorted(ifindex_results.items()):
        last_octet = get_oid_last_octet(oid)
        ifmap[last_octet]['index'] = int(val)

    # VLANs
    ifvlan_oid = '.1.3.6.1.4.1.9.9.68.1.2.2.1.2'
    ifvlan_results = do_snmpwalk(snmpcmd, ifvlan_oid)
    for oid, val in sorted(ifvlan_results.items()): 
        last_octet = get_oid_last_octet(oid)
        ifmap[last_octet]['vlan'] = str(int(val)) 
	
    # vlanTrunkPortDynamicStatus
    ifTrunk_oid = '.1.3.6.1.4.1.9.9.46.1.6.1.1.14'
    ifTrunk_results = do_snmpwalk(snmpcmd, ifTrunk_oid)
    for oid, val in sorted(ifTrunk_results.items()):
    	last_octet = get_oid_last_octet(oid)
        if val == 1:
		ifmap[last_octet]['port_type'] = str("trunk")
	else:
		ifmap[last_octet]['port_type'] = str("access")

    # Oper Status
    ifOperStatus_oid = ".1.3.6.1.2.1.2.2.1.8"
    ifOperStatus_results = do_snmpwalk(snmpcmd, ifOperStatus_oid)
    for oid, val in sorted(ifOperStatus_results.items()):
    	last_octet = get_oid_last_octet(oid)
        ifmap[last_octet]['operstatus'] = int(val)


    # Admin Status
    ifAdminStatus_oid = ".1.3.6.1.2.1.2.2.1.7"
    ifAdminStatus_results = do_snmpwalk(snmpcmd, ifAdminStatus_oid)
    for oid, val in sorted(ifAdminStatus_results.items()):
        last_octet = get_oid_last_octet(oid)
        ifmap[last_octet]['adminstatus'] = int(val)

    # ifPhysAddr
    ifPhysAddress_oid = '.1.3.6.1.2.1.2.2.1.6'
    ifPhysAddress_results = do_snmpwalk(snmpcmd, ifPhysAddress_oid)
    for oid, val in sorted(ifPhysAddress_results.items()):
        last_octet = get_oid_last_octet(oid)
	ifmap[last_octet]['physicalAddress'] = str(val)


    # ifSpeed
    ifSpeed_oid = '.1.3.6.1.2.1.31.1.1.1.15'
    ifSpeed_results = do_snmpwalk(snmpcmd, ifSpeed_oid)
    for oid, val in sorted(ifSpeed_results.items()):
        last_octet = get_oid_last_octet(oid)
        ifmap[last_octet]['speed'] = str(int(val))

    # ifLastChange
    ifLastChange_oid = '.1.3.6.1.2.1.2.2.1.9'
    ifLastChange_results = do_snmpwalk(snmpcmd, ifLastChange_oid)
    for oid, val in sorted(ifLastChange_results.items()):
        last_octet = get_oid_last_octet(oid)
        ifmap[last_octet]['lastchange'] = str(int(val))

		
    # ifHCInOctets
    ifHCInOctets_oid = '.1.3.6.1.2.1.31.1.1.1.6'
    ifHCInOctets_results = do_snmpwalk(snmpcmd, ifHCInOctets_oid)
    for oid, val in sorted(ifHCInOctets_results.items()): 
	last_octet = get_oid_last_octet(oid)
	if val:
		ifmap[last_octet]['ifHCInOctets'] = int(val)
	else:
		ifmap[last_octet]['ifHCInOctets'] = 0
	
    # ifHCOutOctets
    ifHCOutOctets_oid = '.1.3.6.1.2.1.31.1.1.1.10'
    ifHCOutOctets_results = do_snmpwalk(snmpcmd, ifHCOutOctets_oid)
    for oid, val in sorted(ifHCOutOctets_results.items()): 
	last_octet = get_oid_last_octet(oid)
	ifmap[last_octet]['ifHCOutOctets'] = int(val)
 
    # print ifmap
    for key,value in ifmap.iteritems():

	# Lets check for certain interfaces and skip them. They are rubbishhh
        if ifmap[key]['name'] == "Null0":
		continue

	if not ifmap[key]['vlan']:
		ifvlan = "none"
	else:
		ifvlan = ifmap[key]['vlan']

	if ifmap[key]['operstatus'] == 1:
		ifoperstatus = str("up")
	else:
		ifoperstatus = str("down")

        if ifmap[key]['adminstatus'] == 1:
                ifadminstatus = str("up")
        else:
                ifadminstatus = str("down")

    	writeEvent("logtype=ifstat, hostname="+hostname+", ip="+ip+", interface="+ifmap[key]['name']+", description=\""+ifmap[key]['desc']+"\", speed="+ifmap[key]['speed']+", vlan="+ifvlan+", type="+str(ifmap[key]['port_type'])+", operstatus="+ifoperstatus+", adminstatus="+ifadminstatus+", ifHCInOctets="+str(ifmap[key]['ifHCInOctets'])+", ifHCOutOctets="+str(ifmap[key]['ifHCOutOctets'])+", lastchange="+ifmap[key]['lastchange']+",")

    #
    # CDP
    #

    cdpmap = defaultdict(lambda: defaultdict(dict))

    # Neighbour host
    cdp_neighbour_oid = '.1.3.6.1.4.1.9.9.23.1.2.1.1.6.10102'
    cdp_neighbour_results = do_snmpwalk(snmpcmd, cdp_neighbour_oid)
    for oid, val in sorted(cdp_neighbour_results.items()):
	last_octet = get_oid_last_octet(oid)
	cdpmap[last_octet]['neighbour'] = str(val)

    # Remote interface
    cdp_remoteif_oid = '.1.3.6.1.4.1.9.9.23.1.2.1.1.7.10102'
    cdp_remoteif_results = do_snmpwalk(snmpcmd, cdp_remoteif_oid)
    for oid, val in sorted(cdp_remoteif_results.items()):
        last_octet = get_oid_last_octet(oid)           
        cdpmap[last_octet]['remoteif'] = str(val)  
    
    # Remote Model
    cdp_remotemod_oid = '.1.3.6.1.4.1.9.9.23.1.2.1.1.8.10102'
    cdp_remotemod_results = do_snmpwalk(snmpcmd, cdp_remotemod_oid)  
    for oid, val in sorted(cdp_remotemod_results.items()): 
        last_octet = get_oid_last_octet(oid)
        cdpmap[last_octet]['remote_model'] = str(val)   


    # Iterate 
    for key,value in cdpmap.iteritems():

	writeEvent("logtype=cdp, hostname="+hostname+", ip="+ip+", neighbour="+cdpmap[key]['neighbour']+", remoteif="+cdpmap[key]['remoteif']+", remote_model=\""+cdpmap[key]['remote_model']+"\",")


def process_conf():

    # Initialize SNMP variables
    snmpcmd = {}
    snmpcmd['community'] = None
    snmpcmd['ipaddress'] = None
    snmpcmd['secname'] = None
    snmpcmd['version'] = None
    snmpcmd['authpassword'] = None
    snmpcmd['authprotocol'] = None
    snmpcmd['privpassword'] = None
    snmpcmd['privprotocol'] = None
    snmpcmd['port'] = 161
 
    snmpconf = ConfigParser.ConfigParser()
    snmpconf.read(SNMP_CONF)
 
    snmpcmd['community'] = snmpconf.get('default','community') 
    snmpcmd['version'] = snmpconf.getint('default','version')
    snmpcmd['port'] = snmpconf.getint('default','port') 

    if snmpcmd['version'] == 3:  
    	# For v3 only
    	snmpcmd['secname'] = snmpconf.get('default','secName')
    	snmpcmd['authpassword'] = snmpconf.get('default','authpassword') 	
	snmpcmd['authprotocol'] = snmpconf.get('default','authprotocol')
	snmpcmd['privpassword'] = snmpconf.get('default','privpassword')
	snmpcmd['privprotocol'] = snmpconf.get('default','privprotocol')

    if not snmpcmd['version']:
        print 'ERROR: SNMP version not specified'
        sys.exit(2)
 
    if (snmpcmd['version'] == 2) and (not snmpcmd['community']):
        print 'ERROR: SNMPv2 community string not defined'
        sys.exit(2)
 
    return (snmpcmd)
 


if __name__ == "__main__":
    main()
