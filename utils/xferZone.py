#!/usr/bin/env python
##
## Perform a Zone Transfer and output records to 'route53-transfer' CSV
##
import re
import sys
import yaml
import logging
import os.path
import dns.zone
import dns.query
from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *

config_file = 'route53_sync.conf'
csv_out = []

usage = """
  xferZone.py <zone>
  
"""

## Check args
try:
    zone_name = sys.argv[1]
    
except Exception as e:
    print >> sys.stderr, "ERROR: %s" % str(e)
    print >> sys.stderr, usage
    sys.exit(2)

## Read Config
try:
    with open(config_file, 'r') as ymlfile:
        app_conf = yaml.load(ymlfile)

    ymlfile.close()
    
    nameserver = app_conf['nameserver']
    csv_file = app_conf['csv_dir'] + '/' + zone_name + '.csv'
    log_file = app_conf['log_dir']  + '/xferzone.log' 
    
except Exception as e:
    print >> sys.stderr, "ERROR: %s" % str(e)
    print >> sys.stderr, 'Error Parsing Config'
    sys.exit(2)

logging.basicConfig( 
  filename=log_file,
  level=logging.DEBUG,
  format='%(asctime)s %(levelname)s %(message)s',
  datefmt='%Y-%m-%d %H:%M:%S'
)

## Zone Transfer
try:
  logging.info("Requesting AXFR from " + nameserver + " for " + zone_name)  
  logging.debug('zone_name: ' + zone_name)
  logging.debug('nameserver: ' + nameserver)
  zone = dns.zone.from_xfr(dns.query.xfr(nameserver, zone_name))
  
except DNSException, e:
  logging.warning("Zone Transfer Failed")
  logging.debug(e.__class__, e)
  sys.exit(1)


## Start Processing Node  
for name, node in zone.nodes.items():
  logging.info("Processing Node: " + str(name))
    
  if re.match(r'^@',str(name)):
    logging.info("Skipping SOA Data: " + str(name))
    continue
      
  fqdn = str(name) + '.' + str(zone.origin)
  logging.debug("FQDN: " + fqdn)
  
  rdatasets = node.rdatasets
  line = []

  try:
    for rdataset in rdatasets:
      ## BEGIN RDATASET ##     
      for rdata in rdataset:
        ## BEGIN RDATA ##
        ## Currently only handling A, CNAME, and MX Records
        if rdataset.rdtype == MX:
          line_data = { 'name': fqdn, 'type': 'MX', 'value': str(rdata.exchange), 'ttl': rdataset.ttl, 'priority': rdata.preference }
          logging.debug("MX Record: " + str(line_data))
          line.append(line_data)
          
        elif rdataset.rdtype == CNAME:
          line_data = { 'name': fqdn, 'type': 'CNAME', 'value': str(rdata.target), 'ttl': rdataset.ttl }
          logging.debug("CNAME Record: " + str(line_data))
          line.append(line_data)
          
        elif rdataset.rdtype == A:
          line_data = { 'name': fqdn, 'type': 'A', 'value': rdata.address, 'ttl': rdataset.ttl }
          logging.debug("A Record: " + str(line_data))
          line.append(line_data)

        elif rdataset.rdtype == PTR:
          line_data = { 'name': fqdn, 'type': 'PTR', 'value': str(rdata.target), 'ttl': rdataset.ttl }
          logging.debug("PTR Record: " + str(line_data))
          line.append(line_data)
          
        else:
	     logging.warning("Did not match record type: %s" % rdataset.rdtype)
		    
  except DNSException, e:
    logging.warning("Error Parsing Zone Data!")
    logging.debug(e.__class__, e)
    sys.exit(1)

  for l in line:
    if l['type'] in ('A', 'CNAME', 'PTR'):
      csv_line = l['name'] + ',' + l['type'] + ',' + l['value'] + ',' + str(l['ttl']) + ',,,,,'
      csv_out.append(csv_line)
      
    if l['type'] == 'MX':
      csv_line = l['name'] + ',' + l['type'] + ',' + str(l['priority']) + ' ' + l['value'] + ',' + str(l['ttl']) + ',,,,,'
      csv_out.append(csv_line)

## Add CSV Header
csv_header = "NAME,TYPE,VALUE,TTL,REGION,WEIGHT,SETID,FAILOVER,EVALUATE_HEALTH"
logging.debug("Inserting CSV Header: " + csv_header)
csv_out.insert(0,csv_header)

try:
  csv_write = open(csv_file,'w')
  logging.debug("Writing CSV: " + csv_file)

except IOError as e:
  logging.warning("Failed to open CSV: " + csv_file) 
  logging.debug("I/O error({0}): {1}".format(e.errno, e.strerror))
  sys.exit(1)
	  
for r in csv_out:
  logging.debug(r)
  csv_write.write(r + "\n")

logging.debug("Done")
csv_write.close()

