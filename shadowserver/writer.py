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

from cybox.core import Observable

from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.port_object import Port
from cybox.objects.domain_name_object import DomainName
from cybox.objects.whois_object import WhoisEntry
from cybox.objects.whois_object import WhoisRegistrar
from cybox.objects.as_object import AutonomousSystem

from stix.data_marking import Marking, MarkingSpecification, MarkingStructure
from stix.extensions.marking.simple_marking import SimpleMarkingStructure

def main():

    # get args
    parser = argparse.ArgumentParser ( description = "Parse a given CSV from Shadowserver and output STIX XML to stdout"
    , formatter_class=argparse.ArgumentDefaultsHelpFormatter )

    parser.add_argument("--infile","-f", help="input CSV with bot data", default = "bots.csv")

    args = parser.parse_args()


    # setup stix document
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.title = "Bot Server IP addresses"
    stix_header.description = "IP addresses connecting to bot control servers at a given port"
    stix_header.add_package_intent ("Indicators - Watchlist")

    # add marking
    mark = Marking()
    markspec = MarkingSpecification()
    markstruct = SimpleMarkingStructure()
    markstruct.statement = "Usage of this information, including integration into security mechanisms implies agreement with the Shadowserver Terms of Service  available at  https://www.shadowserver.org/wiki/pmwiki.php/Shadowserver/TermsOfService"
    markspec.marking_structures.append(markstruct)
    mark.add_marking(markspec)

    stix_header.handling = mark

    # include author info
    stix_header.information_source = InformationSource()
    stix_header.information_source.time = Time()
    stix_header.information_source.time.produced_time  =datetime.now(tzutc())
    stix_header.information_source.tools = ToolInformationList()
    stix_header.information_source.tools.append("ShadowBotnetIP-STIXParser")
    stix_header.information_source.identity = Identity()
    stix_header.information_source.identity.name = "MITRE STIX Team"
    stix_header.information_source.add_role(VocabString("Format Transformer"))

    src = InformationSource()
    src.description = "https://www.shadowserver.org/wiki/pmwiki.php/Services/Botnet-CCIP"
    srcident = Identity()
    srcident.name = "shadowserver.org"
    src.identity = srcident
    src.add_role(VocabString("Originating Publisher"))
    stix_header.information_source.add_contributing_source(src)

    stix_package.stix_header = stix_header

    # add TTP for overall indicators
    bot_ttp = TTP()
    bot_ttp.title = 'Botnet C2'
    bot_ttp.resources = Resource()
    bot_ttp.resources.infrastructure = Infrastructure()
    bot_ttp.resources.infrastructure.title = 'Botnet C2'

    stix_package.add_ttp(bot_ttp)

    # read input data
    fd = open (args.infile, "rb") 
    infile = csv.DictReader(fd)

    for row in infile:
    # split indicators out, may be 1..n with positional storage, same port and channel, inconsistent delims
        domain = row['Domain'].split()
        country = row['Country'].split()
        region = row['Region'].split('|')
        state = row['State'].split('|')
        asn = row['ASN'].split()
        asname = row['AS Name'].split()
        asdesc = row['AS Description'].split('|')

        index = 0
        for ip in row['IP Address'].split():
            indicator = Indicator()
            indicator.title = "IP indicator for " + row['Channel'] 
            indicator.description = "Bot connecting to control server"


            # point to overall TTP
            indicator.add_indicated_ttp(TTP(idref=bot_ttp.id_))

            # add our IP and port
            sock = SocketAddress()
            sock.ip_address = ip

            # add sighting
            sight = Sighting()
            sight.timestamp = ""
            obs = Observable(item=sock.ip_address)
            obsref = Observable(idref=obs.id_)
            sight.related_observables.append(obsref)
            indicator.sightings.append(sight)

            stix_package.add_observable(obs)

            # add pattern for indicator
            sock_pattern = SocketAddress()
            sock_pattern.ip_address = ip
            port = Port()
            port.port_value = row['Port']
            sock_pattern.port = port

            sock_pattern.ip_address.condition= "Equals"
            sock_pattern.port.port_value.condition= "Equals"

            indicator.add_object(sock_pattern)
            stix_package.add_indicator(indicator)
            
            # add domain
            domain_obj = DomainName()
            domain_obj.value = domain[index]
            domain_obj.add_related(sock.ip_address,"Resolved_To", inline=False)

            stix_package.add_observable(domain_obj)

            # add whois obs
            whois_obj = WhoisEntry()
            registrar = WhoisRegistrar()
            registrar.name = asname[index] 
            registrar.address = state[index] + region[index] + country[index]

            whois_obj.registrar_info = registrar 
            whois_obj.add_related(sock.ip_address,"Characterizes", inline=False)

            stix_package.add_observable(whois_obj)
            
            # add ASN obj
            asn_obj = AutonomousSystem()
            asn_obj.name = asname[index] 
            asn_obj.number = asn[index]
            asn_obj.handle = "AS" + str(asn[index])
            asn_obj.add_related(sock.ip_address,"Contains", inline=False)

            stix_package.add_observable(asn_obj)

            # iterate 
            index = index + 1

    print stix_package.to_xml() 

if __name__ == "__main__":
    main()
