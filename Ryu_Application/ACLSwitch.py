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
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as ofp13_parser
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import packet
from ryu.lib.packet import tcp

# ACLSwitch modules
from ACLSwitchLogging import ACLSwitchLogging

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ACLSwitch(app_manager.RyuApp):
    """Main class for ACLSwitch. Used to create objects and listen for OpenFlow events.
    """

    _TABLE_ID_ACL = 0
    _TABLE_ID_L2 = 1

    def __init__(self, *args, **kwargs):
        # Create logging object first!
        self._logging = ACLSwitchLogging()
        self._logging.info("Starting ACLSwitch...")

        super(ACLSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # Create objects to manage stuff

        # TODO If one of the components fails to start then the application should terminate.
        self._logging.success("ACLSwitch started successfully.")

    # Methods for modifying switch flow tables

    def _add_flow(self, datapath, priority, match, actions,
                  buffer_id=None, time_limit=0, table_id=1):
        """Reactively add a flow table entry to a switch's flow table.

        :param datapath: The switch to add the flow-table entry to.
        :param priority: Priority of the flow-table entry.
        :param match: What packet header fields should be matched.
        :param actions: The behaviour that matching flows should follow.
        :param buffer_id: Identifier of buffer queue if traffic is
        being buffered.
        :param time_limit: When the rule should expire.
        :param table_id: What flow table the flow-table entry should
        be sent to.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if (actions == None):
            # catch the moment where the flow tables are being linked up
            inst = [parser.OFPInstructionGotoTable(self._TABLE_ID_L2)]
        else:
            inst = [
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    hard_timeout=time_limit,
                                    priority=priority, match=match,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    instructions=inst, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    hard_timeout=time_limit,
                                    priority=priority, match=match,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    instructions=inst, table_id=table_id)
        datapath.send_msg(mod)

    # OpenFlow switch event handlers

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, event):
        """Catch and handle OpenFlow Protocol SwitchFeatures events.

        :param event: The OpenFlow event.
        """
        datapath = event.msg.datapath
        datapath_id = event.msg.datapath_id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self._logging.info("Switch \'{0}\' connected.".format(
                datapath_id))

        # Install table-miss flow entry for the ACL flow table. No
        # buffer is used for this table-miss entry as matching flows
        # get passed onto the L2 switching flow table.
        match = parser.OFPMatch()
        # No action required for forwarding to another table
        actions = None
        self._add_flow(datapath, 0, match, actions,
                       table_id=self._TABLE_ID_ACL)

        # Install table-miss flow entry for the L2 switching flow table.
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

        # Take note of switches (via their datapaths)
        # TODO Activate the following once policy domains have been implemented.
        #dp_id = ev.msg.datapath_id
        #self._connected_switches[dp_id] = [self.POLICY_DEFAULT]

        # Distribute the list of rules to the switch
        #self._distribute_rules_policy_set(datapath, self.POLICY_DEFAULT)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved)
    def _flow_removed_handler(self, event):
        """Catch and handle OpenFlow Protocol FlowRemoved events.

        :param event: The OpenFlow event.
        """
        msg = event.msg
        match = msg.match
        self._logging.info("Flow table entry removed.\n\t Flow match: "
                           "{0}".format(match))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, event):
        """Catch and handle OpenFlow Protocol PacketIn events.

        This method should only be invoked when a desirable packet
        passes all firewall filtering and needs to forwarded towards
        the destination host. Therefore this method provides a naive
        Ethernet forwarding mechanism. THis method has been adapted
        from simple_switch_13.py.

        :param event: The OpenFlow event.
        """
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if event.msg.msg_len < event.msg.total_len:
            self._logging.warning("Packet truncated: only {0} of {1} "
                                  "bytes".format(event.msg.msg_len,
                                                 event.msg.total_len))
        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_head = pkt.get_protocols(ethernet.ethernet)[0]

        eth_dst = eth_head.dst
        eth_src = eth_head.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self._logging.info("Packet in\t-\tData-path ID: {0}, Source "
                           "Ethernet: {1}, Destination Ethernet: {2}, "
                           "Ingress switch port: {3}".format(dpid,
                                                             eth_src,
                                                             eth_dst,
                                                             in_port))

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][eth_src] = in_port

        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)

            self._logging.info("New flow\t-\t{0}".format(pkt))
            priority = ofproto_v1_3.OFP_DEFAULT_PRIORITY

            # verify if we have a valid buffer_id, if yes avoid to send
            # both flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._add_flow(datapath, priority, match, actions,
                               msg.buffer_id)
                return
            else:
                self._add_flow(datapath, priority, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions,
                                  data=data)
        datapath.send_msg(out)
