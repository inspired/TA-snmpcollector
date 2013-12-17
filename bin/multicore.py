#!/usr/bin/env python2.6
"""
This is a multiprocessing wrapper for Net-SNMP.
This makes a synchronous API asynchronous by combining
it with Python2.6

"""

import netsnmp
import os
import sys
from collections import defaultdict
import netsnmp
import json
import ConfigParser
import time
from multiprocessing import Process, Queue, current_process

SPLUNK_HOME = '/opt/splunk'
DEVICES_CONF = 'local/switches.conf'
SNMP_CONF = 'local/snmp.conf'

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


class HostRecord():
    """This creates a host record"""
    def __init__(self,
                 hostname = None,
                 query = None):
        
        self.hostname = hostname
        self.query = query

class SnmpSession():
    """A SNMP Session"""
    def __init__(self,
                oid = "sysDescr",
                Version = 2,
                DestHost = "10.215.32.101",
                Community = "daxdemo01",
                Verbose = True,
                ):
        self.oid = oid        
        self.Version = Version
        self.DestHost = DestHost
        self.Community = Community
        self.Verbose = Verbose
        self.var = netsnmp.Varbind(oid, 0)
        self.hostrec = HostRecord()
        self.hostrec.hostname = self.DestHost
        
    def query(self):
        """Creates SNMP query
        
        Fills out a Host Object and returns result
        """
        try:
            result = netsnmp.snmpget(self.var,
                                Version = self.Version,
                                DestHost = self.DestHost,
                                Community = self.Community)
            self.hostrec.query = result
        except Exception, err:
            if self.Verbose:    
                print err
            self.hostrec.query = None
        finally:
            #return self.hostrec
        
def make_query(host):
    """This does the actual snmp query
    
    This is a bit fancy as it accepts both instances
    of SnmpSession and host/ip addresses.  This
    allows a user to customize mass queries with
    subsets of different hostnames and community strings
    
    """
    if isinstance(host,SnmpSession):
        return host.query()
    else:
        s = SnmpSession(DestHost=host)
        return s.query()
    
# Function run by worker processes
def worker(input, output):
    for func in iter(input.get, 'STOP'):
        result = make_query(func)
        output.put(result)
        
def main():
    """Runs everything"""
    
    # Create queues
    task_queue = Queue()
    done_queue = Queue()
    
    #submit tasks
    #for host in hosts:
    #    task_queue.put(host)
    os.chdir(SPLUNK_HOME + '/etc/apps/TA-snmpcollector/')
    # Process the configuration
    (snmpcmd) = process_conf()

    with open(DEVICES_CONF, 'r') as devices:
	NUMBER_OF_PROCESSES = 0
        for line in devices:
	    NUMBER_OF_PROCESSES = NUMBER_OF_PROCESSES + 1
	    task_queue.put(line)

    #Start worker processes
    for i in range(NUMBER_OF_PROCESSES):
        Process(target=worker, args=(task_queue, done_queue)).start()
    
     # Get and print results
    print 'Unordered results:'
    for i in range(NUMBER_OF_PROCESSES):
        print '\t', done_queue.get().query    
    
    # Tell child processes to stop
    for i in range(NUMBER_OF_PROCESSES):
        task_queue.put('STOP')
        print "Stopping Process #%s" % i
        
if __name__ == "__main__":
    main()
