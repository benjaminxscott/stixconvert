#!/usr/bin/env python

from stix.core import STIXPackage
import sys

try: fname = sys.argv[1]
except: exit(1)
fd = open(sys.argv[1])
stix_package = STIXPackage.from_xml(fd)

for ind in stix_package.indicators:
    print "Title: " + ind.title
    print "Desc: " + str(ind.description)
    for obs in ind.observables:
        obs = obs.to_dict()
        print "IP "+ obs['object']['properties']['ip_address']['address_value']['value']

for obs in stix_package.observables.observables:
    obs = obs.to_dict()
    obstype = obs['object']['properties']['xsi:type']
    if 'Domain' in obstype:
        print "Domain: " + obs['object']['properties']['value']
    elif 'Address' in obstype:
        print "ASN: " + obs['object']['properties']['address_value']
    elif 'Whois' in obstype:
        print "Whois: " + obs['object']['properties']['registrar_info']['address']

