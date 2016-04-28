# Copyright 2016 Jarrod N. Bakker
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#########################################################################
# Author: Jarrod N. Bakker
#
# ACLSwitch was originally developed as part of an ENGR489 project at
# Victoria University of Wellington during 2015.
#
# This file contains the implementation of ACLSwitch since ENGR489 in
# 2015.
#
# The original license for simple_switch_13.py can be found below.
#
#########################################################################
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#########################################################################

# Ryu and OpenFlow modules
from ryu.controller.ofp_event import EventOFPSwitchFeatures
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as ofp13_parser

# ACLSwitch modules
from abc_ryu_app import ABCRyuApp
from aclswitch_api import ACLSwitchAPI
from aclswitch_api import ReturnStatus
from aclswitch_logging import ACLSwitchLogging
from flow.flow_manager import FlowManager
from rest_wsgi import ACLSwitchREST

# Other modules
from netaddr import IPAddress  # TODO Does Ryu have a friendly packet library
import json
import os

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ACLSwitch(ABCRyuApp):
    """Main class for ACLSwitch.
    """

    _APP_NAME = "ACLSwitch"
    _CONFIG_FILE_NAME = "config.json"
    _EXPECTED_HANDLERS = (EventOFPSwitchFeatures.__name__, )
    _INSTANCE_NAME_ASW_API = "asw_api"
    # Default priority is defined to be in the middle (0x8000 in 1.3)
    # Note that for a priority p, 0 <= p <= MAX (i.e. 65535)
    _OFP_MAX_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY * 2 - 1
    _POLICY_DEFAULT = "default"
    _TABLE_ID_ACL = 0
    # The value below should be obtained through some kind of api call
    # with the controller. ACLSwitch should have no idea what the
    # other app is, just what table is being used next in the pipeline.
    _TABLE_ID_L2 = 1


    def __init__(self, contr):
        self._logging = ACLSwitchLogging()
        self._contr = contr
        self._supported = self._verify_contr_handlers()
        self._logging.info("Starting ACLSwitch...")

        # Create objects to manage different features
        self._flow_man = FlowManager(self, self._logging)
        self._api = ACLSwitchAPI(self._logging, self._flow_man)

        # Read config file
        # TODO Command line argument for custom location for config file
        file_loc = (os.path.dirname(__file__) + "/" +
                    self._CONFIG_FILE_NAME)
        self._import_config_file(file_loc)

        self._init_policies = [self._POLICY_DEFAULT]

        # Register REST WSGI through the controller app
        self._contr.register_rest_wsgi(ACLSwitchREST, kwargs=
                                       {self._INSTANCE_NAME_ASW_API:
                                        self._api})

        self._logging.success("ACLSwitch started successfully.")

    def _import_config_file(self, file_loc):
        """Import ACLSwitch config from a JSON-formatted file.

        :param file_loc: Path to the configuration file.
        :return:
        """
        # check that file exists
        # READ!
        try:
            # TODO use aclswitch_logging
            buf_in = open(file_loc)
            self._logging.info("Reading config from file: " + file_loc)
            for line in buf_in:
                if line[0] == "#" or not line.strip():
                    continue  # Skip file comments and empty lines
                try:
                    config = json.loads(line)
                except ValueError:
                    self._logging.fail(line + " is not valid JSON.")
                    continue
                if "rule" in config:
                    # TODO Change time-enforced rule syntax to overload normal rule syntax
                    self._logging.info("Parsing rule: {0}".format(
                        config["rule"]))
                    result = self._api.acl_create_rule(config["rule"])
                    # TODO Handle return codes from API
                    self._logging.info("Return code: {0}".format(result))
                    #if result[0] is True:
                    #    self._logging.success("Rule created: {"
                    #                          "0}".format(config[
                    #
                    # "rule"]))
                    #else:
                    #    self._logging.fail("Rule creation failed: {"
                    #                       "0}".format(result[1]))
                elif "policy" in config:
                    self._logging.info("Parsing policy domain: {"
                                       "0}".format(config["policy"]))
                    result = self._api.policy_create(config["policy"])
                    self._logging.info("Return code: {0}".format(result))
                else:
                    self._logging.fail(line + "is not recognised JSON.")
            buf_in.close()
        except IOError:
            self._logging.fail("Unable to read from file: " +
                               str(file_loc))

    def add_blacklist_entry(self, switch_id, rule):
        """Add a rule to the blacklist flow table as a flow table entry.

        :param switch_id: The switch to add an entry to.
        :param rule: The rule to add.
        """
        datapath = self._contr.switch_get_datapath(switch_id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        priority = self._OFP_MAX_PRIORITY
        actions = []
        match = self._create_match(rule)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self._contr.add_flow(datapath, priority, match, inst, 0,
                             self._TABLE_ID_ACL)

    def remove_blacklist_entry(self, switch_id, rule):
        """Remove a blacklist flow table entry.

        :param switch_id: The switch to remove the entry from.
        :param rule: The rule to remove.
        """
        datapath = self._contr.switch_get_datapath(switch_id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        remove_type = ofproto.OFPFC_DELETE_STRICT
        priority = self._OFP_MAX_PRIORITY
        match = self._create_match(rule)
        out_port = ofproto.OFPP_ANY
        out_group = ofproto.OFPG_ANY
        self._contr.remove_flow(datapath, parser, remove_type, priority,
                                match, out_port, out_group)

    def _create_match(self, rule):
        """Create an OFPMatch instance based on the contents of an
        ACL_ENTRY.

        :param rule: The rule entry to create an OFPMatch instance from.
        :return: The OFPMatch instance.
        """
        # TODO make "*" a constant
        match = ofp13_parser.OFPMatch()
        ip_version = self._return_ip_version(rule.ip_src, rule.ip_dst)
        # Match IP layer (layer 3)
        if ip_version == 4:
            # Match IPv4
            match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,
                               ethernet.ether.ETH_TYPE_IP)
            if rule.ip_src != "*":
                match.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC,
                                   int(IPAddress(rule.ip_src)))
            if rule.ip_dst != "*":
                match.append_field(ofproto_v1_3.OXM_OF_IPV4_DST,
                                   int(IPAddress(rule.ip_dst)))
        else:
            # Match IPv6
            match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,
                               ethernet.ether.ETH_TYPE_IPV6)
            if rule.ip_src != "*":
                match.append_field(ofproto_v1_3.OXM_OF_IPV6_SRC,
                                   IPAddress(rule.ip_src).words)
            if rule.ip_dst != "*":
                match.append_field(ofproto_v1_3.OXM_OF_IPV6_DST,
                                   IPAddress(rule.ip_dst).words)

        # Match transport layer (layer 4)
        if rule.tp_proto != "*":
            if rule.tp_proto == "tcp":
                # Match TCP
                match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                   ipv4.inet.IPPROTO_TCP)  # covers IPv6
                if rule.port_src != "*":
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_SRC,
                                       int(rule.port_src))
                if rule.port_dst != "*":
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_DST,
                                       int(rule.port_dst))
            elif rule.tp_proto == "udp":
                # Match UDP
                match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                   ipv4.inet.IPPROTO_UDP)  # covers IPv6
                if rule.port_src != "*":
                    match.append_field(ofproto_v1_3.OXM_OF_UDP_SRC,
                                       int(rule.port_src))
                if rule.port_dst != "*":
                    match.append_field(ofproto_v1_3.OXM_OF_UDP_DST,
                                       int(rule.port_dst))
        return match

    def _return_ip_version(self, ip_src, ip_dst):
        """Return the IP version being used given the source and
        destination addresses.

        :param ip_src: the source IP address to check.
        :param ip_dst: the destination IP address to check.
        :return: the IP version being used.
        """
        if "*" not in ip_src:
            return IPAddress(ip_src).version
        else:
            return IPAddress(ip_dst).version

    def switch_features(self, event):
        """Process a switch features event from the controller.

        :param event: The OpenFlow event.
        """
        datapath = event.msg.datapath
        datapath_id = event.msg.datapath_id
        parser = datapath.ofproto_parser

        # Install table-miss flow entry for the ACL flow table. No
        # buffer is used for this table-miss entry as matching flows
        # get passed onto the L2 switching flow table.
        # TODO This should be managed by the ACLManager?
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(self._TABLE_ID_L2)]
        self._contr.add_flow(datapath, 0, match, inst, 0,
                             self._TABLE_ID_ACL)
        # Take note of switches (via their datapaths IDs)
        self._api.policy_add_switch(datapath_id, self._init_policies)

    def get_app_name(self):
        return self._APP_NAME

    def get_expected_handlers(self):
        return self._EXPECTED_HANDLERS

    def is_supported(self):
        return self._supported

    def _verify_contr_handlers(self):
        contr_handlers = self._contr.get_ofpe_handlers()
        failures = ()
        for expected_h in self._EXPECTED_HANDLERS:
            if expected_h not in contr_handlers:
                failures = failures + (expected_h,)
        if not len(failures) == 0:
            fail_msg = ("{0}: The following OpenFlow protocol events "
                        "are not supported by the controller:".format(
                         self._APP_NAME))
            for f in failures:
                fail_msg += "\n\t- {0}".format(f)
            self._logging.fail(fail_msg)
            return False
        else:
            return True
