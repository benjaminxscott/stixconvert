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
from cybox.common import Hash

from cybox.objects.email_message_object import EmailMessage
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.port_object import Port
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.objects.mutex_object import Mutex
from cybox.objects.http_session_object import *
from cybox.objects.win_registry_key_object import RegistryValue

from stix.common.kill_chains import KillChainPhasesReference, KillChain, KillChainPhase

def main():
 
 
    # TODO create a empty package for each groupID with title and intent of GID, point to relevant inds as related_indicators
    # TODO point each relevant ind to empty package as releated_package

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

    # create kill chain with three options (pre, post, unknown), relate as needed
    pre = KillChainPhase(phase_id="cert_five:pre", name="Pre-infection indicator", ordinality=1)
    post = KillChainPhase(phase_id="cert_five:post", name="Post-infection indicator", ordinality=2)
    unk = KillChainPhase(phase_id="cert_five:unknown", name="Unknown ")
    chain = KillChain(id_="cert_five:cyber-kill-chain")
    chain.kill_chain_phases = [pre, post, unk]
    stix_package.ttps.kill_chains.append(chain)

    # read input data
    fd = open (args.infile, "rb") 
    infile = csv.DictReader(fd)

    for row in infile:
        # print row
        error = False
        ind = Indicator()
        ind.alternative_id = row['IndicatorID']
        ind.title = "Indicator with ID " + row['IndicatorID'] 
        ind.description = row['Notes']
        ind.producer = InformationSource()
        ind.producer.description = row['Reference']

        # set chain phase
        if 'Pre' in row['InfectionType']:
            ind.kill_chain_phases.append(pre.phase_id)
        elif 'Post' in row['InfectionType']:
            ind.kill_chain_phases.append(post.phase_id)
        else:
            ind.kill_chain_phases.append(unk.phase_id)
 
        # XXX currently unknown purpose for 'Malware' field - we omit since it sees to be content-free
            # another solution might relate as 'Malware TTP' to the indicator

        # XXX omitting HTTP content and useragent until we have real example data


        # XXX we omit indicatortype from output since it's implied in cybox type 
        ind_type = row['IndicatorType']
        if 'IP' in ind_type:
            ind_obj = SocketAddress()
            ind_obj.ip_address = row['Indicator']
            ind_obj.ip_address.condition= "Equals"
            if row['indValue']:
                port = Port()
                port.port_value = row['indValue']
                port.port_value.condition= "Equals"
                ind_obj.port = port


        elif 'Domain' in ind_type:
            ind_obj = DomainName()
            ind_obj.value = row['Indicator']
            ind_obj.value.condition= "Equals"

        elif 'Email' in ind_type:
            ind_obj = EmailMessage()
            ind_obj.subject = row['Indicator']
            # XXX unknown where real data keeps sender name

        elif 'UserAgent' in ind_type:
            # XXX this method can be used to encode other HTTP headers as well
            fields = HTTPRequestHeaderFields()
            fields.user_agent = row['Indicator']
            fields.user_agent.condition = "Equals"
            header = HTTPRequestHeader()
            header.parsed_header = fields

            request = HTTPClientRequest()
            request.http_request_header = header

            ind_obj = HTTPSession()
            ind_obj.http_request_response = [request]
            
        elif 'URL' in ind_type:
            request = HTTPClientRequest()
            request.http_request_line = HTTPRequestLine()
            request.http_request_line.http_method = row['Indicator'].split()[0]
            request.http_request_line.value = row['Indicator'].split()[1]
            request.http_request_line.value.condition = "Equals" 

            ind_obj = HTTPSession()
            ind_obj.http_request_response = [request]


        elif 'File' in ind_type:
            print "nope"
            ind_obj = File()
            ind_obj.file_name = row['Indicator']
            digest = Hash()
            # XXX assumes that hash digests are stored in this field in real data
            digest.simple_hash_value = row['indValue']
            digest.simple_hash_value.condition = "Equals"

            ind_obj.add_hash(digest)

        elif 'Registry' in ind_type:
            ind_obj = RegistryValue()
            ind_obj.name = row['Indicator']
            ind_obj.data = row['indValue']

        elif 'Mutex' in ind_type:
            ind_obj = Mutex()
            ind_obj.name = row['Indicator']
            ind_obj.name.condition= "Equals"

        else:
            print "ERR type not supported: " + ind_type + " <- will be omitted from output"
            error = True

        if not error:
            # all good, add to package
            ind.add_object(ind_obj)
            stix_package.add_indicator(ind)


    print stix_package.to_xml() 

if __name__ == "__main__":
    main()
