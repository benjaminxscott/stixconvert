#!/usr/bin/env python

import csv
import argparse

from stix.ttp import TTP, Resource
from stix.ttp.infrastructure import Infrastructure

from datetime import datetime
from dateutil.tz import tzutc
from stix.indicator import Indicator
from stix.indicator.sightings import Sighting

from stix.core import STIXPackage, STIXHeader
from stix.common import (InformationSource, Identity, RelatedObservable,
                         VocabString)
from cybox.common import ToolInformationList, Time

from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.port_object import Port
from cybox.objects.domain_name_object import DomainName


def main():
    # TODO create three phase kill chain for infectiontype, relate as needed
    # TODO drop indicatortype since it's implied in the cybox output

    # get args
    parser = argparse.ArgumentParser ( description = "Parse a given CSV and output STIX XML" 
    , formatter_class=argparse.ArgumentDefaultsHelpFormatter )

    parser.add_argument("--infile","-f", help="input CSV", default = "in.csv")

    args = parser.parse_args()

    # setup header
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.title = "Indicators"
    stix_header.add_package_intent ("Indicators - Watchlist")

    stix_package.stix_header = stix_header

    # read input data
    fd = open (args.infile, "rb") 
    infile = csv.DictReader(fd)

    for row in infile:
        indicator = Indicator()
        indicator.title = "Indicator with ID " + row['IndicatorID'] 
        indicator.description = row['Notes']
        indicator.producer = InformationSource()
        indicator.producer.description = row['Reference']
        stix_package.add_indicator(indicator)
        # TODO set ID as alternativeID (unknown where that lives)

        # TODO either use related_ttp -> malware or just omit 
        #indicator.add_indicated_ttp(TTP(idref=bot_ttp.id_))

        """
        # TODO switch on 'type' and emit cybox pattern based on indicator
        # TODO include indValue if applicable (i.e. if HTTP and needs Port)
        sock = SocketAddress()
        sock.ip_address = ip

        # add pattern for indicator
        sock_pattern = SocketAddress()
        sock_pattern.ip_address = ip
        port = Port()
        port.port_value = row['Port']
        sock_pattern.port = port

        sock_pattern.ip_address.condition= "Equals"
        sock_pattern.port.port_value.condition= "Equals"

        indicator.add_object(sock_pattern)
        
        # add domain
        domain_obj = DomainName()
        domain_obj.value = domain[index]
        domain_obj.add_related(sock.ip_address,"Resolved_To", inline=False)

        stix_package.add_observable(domain_obj)

        """

    print stix_package.to_xml() 

if __name__ == "__main__":
    main()
