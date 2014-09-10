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
from cybox.objects.win_registry_key_object import *

from stix.common.kill_chains import KillChainPhase, KillChain, KillChainPhaseReference

def main():
    # get args
    parser = argparse.ArgumentParser ( description = "Parse a given CSV and output STIX XML" 
    , formatter_class=argparse.ArgumentDefaultsHelpFormatter )

    parser.add_argument("--infile","-f", help="input CSV", default = "in.csv")

    args = parser.parse_args()

    # setup header
    contain_pkg = STIXPackage()
    stix_header = STIXHeader()
    stix_header.title = "Indicators"
    stix_header.add_package_intent ("Indicators - Watchlist")

    contain_pkg.stix_header = stix_header


    # create kill chain with three options (pre, post, unknown), relate as needed
    pre = KillChainPhaseReference(phase_id="u5:pre", name="Pre-infection indicator", ordinality=1,kill_chain_id="u5:KillChain-7808F4B3-61A1-429C-9E05-1D7B9D18A895")
    post = KillChainPhaseReference(phase_id="u5:post", name="Post-infection indicator", ordinality=2,kill_chain_id="u5:KillChain-7808F4B3-61A1-429C-9E05-1D7B9D18A895")
    unk = KillChainPhaseReference(phase_id="u5:unknown", name="Unknown",kill_chain_id="u5:KillChain-7808F4B3-61A1-429C-9E05-1D7B9D18A895")
    chain = KillChain(id_="u5:KillChain-7808F4B3-61A1-429C-9E05-1D7B9D18A895")
    chain.kill_chain_phases = [pre, post, unk]
    contain_pkg.ttps.kill_chains.append(chain)

    # read input data
    fd = open (args.infile, "rb") 
    infile = csv.DictReader(fd)

    for row in infile:
        # create indicator for each row
        error = False
        ind = Indicator()
        ind.add_alternative_id(row['GroupID'])
        ind.title = "Indicator with ID " + row['IndicatorID'] 
        ind.description = row['Notes']
        ind.producer = InformationSource()
        ind.producer.description = row['Reference']

        # XXX unknown purpose for 'Malware' field - omitted
            # if the field denotes a specific malware family, we might relate as 'Malware TTP' to the indicator

        # set chain phase
        if 'Pre' in row['InfectionType']:
            ind.kill_chain_phases.append(pre.phase_id)
        elif 'Post' in row['InfectionType']:
            ind.kill_chain_phases.append(post.phase_id)
        else:
            ind.kill_chain_phases.append(unk.phase_id)
 

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
            ind_obj.subject.condition= "Equals"
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
            request.http_request_line.http_method.condition = "Equals" 
            request.http_request_line.value = row['Indicator'].split()[1]
            request.http_request_line.value.condition = "Equals" 

            ind_obj = HTTPSession()
            ind_obj.http_request_response = [request]


        elif 'File' in ind_type:
            ind_obj = File()
            ind_obj.file_name = row['Indicator']
            ind_obj.file_name.condition = "Equals"
            digest = Hash()
            # XXX assumes that hash digests are stored in this field in real data
            digest.simple_hash_value = row['indValue']
            digest.simple_hash_value.condition = "Equals"

            ind_obj.add_hash(digest)

        elif 'Registry' in ind_type:
            ind_obj = WinRegistryKey()
            keys = RegistryValues()
            key = RegistryValue()
            key.name = row['Indicator']
            key.name.condition = "Equals"
            key.data = row['indValue']
            key.data.condition = "Equals"
            keys.append(key)
            ind_obj.values = keys

        elif 'Mutex' in ind_type:
            ind_obj = Mutex()
            ind_obj.name = row['Indicator']
            ind_obj.name.condition= "Equals"

        else:
            print "ERR type not supported: " + ind_type + " <- will be omitted from output"
            error = True


        
        # finalize indicator
        if not error:
            ind.add_object(ind_obj)
            contain_pkg.add_indicator(ind)

    # DONE looping

    print contain_pkg.to_xml(include_namespaces=False) 

if __name__ == "__main__":
    main()
