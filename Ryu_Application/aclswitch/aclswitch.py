# Copyright 2015 Jarrod N. Bakker
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
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
#########################################################################

# Ryu and OpenFlow modules
from ryu.controller.ofp_event import EventOFPSwitchFeatures
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as ofp13_parser

# ACLSwitch modules
from abc_ryu_app import ABCRyuApp
from aclswitch.aclswitch_api import ACLSwitchAPI
from aclswitch.config_loader import ConfigLoader
from aclswitch.flow.flow_manager import FlowManager
from aclswitch.rest_wsgi import ACLSwitchREST

# Other modules
from netaddr import IPAddress
import logging
import os

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ACLSwitch(ABCRyuApp):
    """Main class for ACLSwitch.
    """

    _APP_NAME = "ACLSwitch"
    _CONFIG_POLICIES_FILE_NAME = "policy_domains.yaml"
    _CONFIG_RULE_FILE_NAME = "acl_rules.yaml"
    _EXPECTED_HANDLERS = (EventOFPSwitchFeatures.__name__, )
    _INSTANCE_NAME_ASW_API = "asw_api"
    # Default priority is defined to be in the middle (0x8000 in 1.3)
    # Note that for a priority p, 0 <= p <= MAX (i.e. 65535)
    _OFP_MAX_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY * 2 - 1
    _POLICY_DEFAULT = "default"
    _RULE_TCP = "tcp"
    _RULE_UDP = "udp"
    _RULE_WILDCARD = "*"
    # TODO Table IDs should be obtained from an application with higher knowledge.
    # An api call to the controller. ACLSwitch should have no idea what
    # what other apps have what table IDS, just what table to forward
    # entries onto.
    _VERSION = "1.1.0"

    def __init__(self, contr):
        # Load config
        path_to_config = os.path.dirname(__file__) + "/config/"
        self._config = ConfigLoader(path_to_config +
                                    self._CONFIG_POLICIES_FILE_NAME,
                                    path_to_config +
                                    self._CONFIG_RULE_FILE_NAME)
        # Set logging
        logging_config = self._config.get_logging_config()
        self._logging = logging.getLogger(__name__)
        self._logging.setLevel(logging_config["min_lvl"])
        self._logging.propagate = logging_config["propagate"]
        self._logging.addHandler(logging_config["handler"])

        # Set flow table numbers
        self._table_id_blacklist = 0
        self._table_id_whitelist = 1
        self._table_id_next = 2

        self._contr = contr
        self._supported = self._verify_contr_handlers()
        self._logging.info("Starting ACLSwitch...")

        # Create objects to manage different features
        self._flow_man = FlowManager(self, logging_config)
        self._api = ACLSwitchAPI(logging_config, self._VERSION,
                                 self._flow_man)
        self._api.policy_create(self._POLICY_DEFAULT)

        # Read config files
        # TODO Command line argument for custom location for config file
        policies, pd_assignments = self._config.load_policies()
        rules = self._config.load_rules()
        for pol in policies:
            self._api.policy_create(pol)
        for rule in rules:
            self._api.acl_create_rule(rule)
        for assignment in pd_assignments:
            self._api.switch_register(assignment["switch_id"])
            self._api.policy_assign_switch(assignment["switch_id"],
                                           assignment["policy"],
                                           from_file=True)

        # Register REST WSGI through the controller app
        self._contr.register_rest_wsgi(ACLSwitchREST, kwargs={
            self._INSTANCE_NAME_ASW_API: self._api})

        self._logging.info("ACLSwitch started successfully.")

    def add_acl_fte(self, switch_id, rule):
        """Add a rule to the flow table as a flow table entry.

        :param switch_id: The switch to add an entry to.
        :param rule: The rule to add.
        """
        datapath = self._contr.switch_get_datapath(switch_id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        priority = self._OFP_MAX_PRIORITY
        if rule.action == "drop":
            actions = []
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
            table = self._table_id_blacklist
        else:
            inst = [parser.OFPInstructionGotoTable(self._table_id_next)]
            table = self._table_id_whitelist
        match = self._create_match(rule)
        if rule.time_enforce == "N/A":
            hard_timeout = 0
        else:
            hard_timeout = rule.time_enforce[1]
        self._contr.add_flow(datapath, priority, match, inst,
                             hard_timeout, table)

    def remove_acl_fte(self, switch_id, rule):
        """Remove a flow table entry.

        :param switch_id: The switch to remove the entry from.
        :param rule: The rule to remove.
        """
        datapath = self._contr.switch_get_datapath(switch_id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        table = self._table_id_blacklist if rule.action == "drop" else\
            self._table_id_whitelist
        remove_type = ofproto.OFPFC_DELETE_STRICT
        priority = self._OFP_MAX_PRIORITY
        match = self._create_match(rule)
        out_port = ofproto.OFPP_ANY
        out_group = ofproto.OFPG_ANY
        self._contr.remove_flow(datapath, parser, table, remove_type,
                                priority, match, out_port, out_group)

    def _create_match(self, rule):
        """Create an OFPMatch instance based on the contents of an
        ACL_ENTRY.

        :param rule: The rule entry to create an OFPMatch instance from.
        :return: The OFPMatch instance.
        """
        match = ofp13_parser.OFPMatch()
        ip_version = self._return_ip_version(rule.ip_src, rule.ip_dst)
        # Match IP layer (layer 3)
        if ip_version == 4:
            # Match IPv4
            match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,
                               ethernet.ether.ETH_TYPE_IP)
            if rule.ip_src != self._RULE_WILDCARD:
                match.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC,
                                   int(IPAddress(rule.ip_src)))
            if rule.ip_dst != self._RULE_WILDCARD:
                match.append_field(ofproto_v1_3.OXM_OF_IPV4_DST,
                                   int(IPAddress(rule.ip_dst)))
        else:
            # Match IPv6
            match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,
                               ethernet.ether.ETH_TYPE_IPV6)
            if rule.ip_src != self._RULE_WILDCARD:
                match.append_field(ofproto_v1_3.OXM_OF_IPV6_SRC,
                                   IPAddress(rule.ip_src).words)
            if rule.ip_dst != self._RULE_WILDCARD:
                match.append_field(ofproto_v1_3.OXM_OF_IPV6_DST,
                                   IPAddress(rule.ip_dst).words)

        # Match transport layer (layer 4)
        if rule.tp_proto != self._RULE_WILDCARD:
            if rule.tp_proto == self._RULE_TCP:
                # Match TCP
                match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                   ipv4.inet.IPPROTO_TCP)  # covers IPv6
                if rule.port_src != self._RULE_WILDCARD:
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_SRC,
                                       int(rule.port_src))
                if rule.port_dst != self._RULE_WILDCARD:
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_DST,
                                       int(rule.port_dst))
            elif rule.tp_proto == self._RULE_UDP:
                # Match UDP
                match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                   ipv4.inet.IPPROTO_UDP)  # covers IPv6
                if rule.port_src != self._RULE_WILDCARD:
                    match.append_field(ofproto_v1_3.OXM_OF_UDP_SRC,
                                       int(rule.port_src))
                if rule.port_dst != self._RULE_WILDCARD:
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
        if self._RULE_WILDCARD not in ip_src:
            return IPAddress(ip_src).version
        else:
            return IPAddress(ip_dst).version

    def switch_features(self, event):
        """Process a switch features event from the controller.

        :param event: The OpenFlow event.
        """
        datapath = event.msg.datapath
        datapath_id = event.msg.datapath_id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Establish the flow table pipeline used by ACLSwitch. The
        # first flow table represents a blacklist for dropping flows
        # and the second flow table represents a whitelist for
        # allowing flows. We must set the appropriate table miss
        # entries and allow ARP traffic through the whitelist.

        # Table miss entries
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(self._table_id_whitelist)]
        self._contr.add_flow(datapath, 0, match, inst, 0,
                             self._table_id_blacklist)
        actions = []
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self._contr.add_flow(datapath, 0, match, inst, 0,
                             self._table_id_whitelist)
        # ARP entries
        inst = [parser.OFPInstructionGotoTable(self._table_id_next)]
        match = parser.OFPMatch(arp_op=arp.ARP_REQUEST,
                                eth_type=ethernet.ether.ETH_TYPE_ARP)
        self._contr.add_flow(datapath, 1, match, inst, 0,
                             self._table_id_whitelist)
        match = parser.OFPMatch(arp_op=arp.ARP_REPLY,
                                eth_type=ethernet.ether.ETH_TYPE_ARP)
        self._contr.add_flow(datapath, 1, match, inst, 0,
                             self._table_id_whitelist)

        # Registered the switch, assign the default policy, then set
        # to a connected state. Once connected, the rules will be sent
        # to the switch.
        self._api.switch_register(datapath_id)
        self._api.policy_assign_switch(datapath_id, self._POLICY_DEFAULT)
        self._api.switch_connect(datapath_id)

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
            self._logging.critical(fail_msg)
            return False
        else:
            return True
