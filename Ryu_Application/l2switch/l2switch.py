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
#
#########################################################################
#
# This is code is based on simple_switch_13.py from
# https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch_13.py.
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

# Module imports
from ryu.controller.ofp_event import EventOFPPacketIn
from ryu.controller.ofp_event import EventOFPSwitchFeatures
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet

from abc_ryu_app import ABCRyuApp

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class L2Switch(ABCRyuApp):
    """A simple application for learning MAC addresses and
    establishing MAC-to-switch-port mappings.
    """

    _APP_NAME = "L2Switch"
    _EXPECTED_HANDLERS = (EventOFPPacketIn.__name__,
                          EventOFPSwitchFeatures.__name__)

    def __init__(self, contr):
        self._contr = contr
        self._table_id_l2 = 2
        self.mac_to_port = {}
        self._supported = self._verify_contr_handlers()
            
    def packet_in(self, event):
        """Process a packet-in event from the controller.

        :param event: The OpenFlow event.
        """
        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        if msg.table_id != self._table_id_l2:
	    #print "l2switch packet " + str( packet.Packet(msg.data))
            print "l2switch not dealing with packet in messages from other tables. table id: " + str(msg.table_id)
            return

        pkt = packet.Packet(msg.data)
        eth_head = pkt.get_protocols(ethernet.ethernet)[0]

        eth_dst = eth_head.dst
        eth_src = eth_head.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        print("{0}: Packet in\t-\tData-path ID: {1}, Source Ethernet: "
              "{2}, Destination Ethernet: {3}, Ingress switch port: "
              "{4}".format(self._APP_NAME, dpid, eth_src, eth_dst,
              in_port))

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][eth_src] = in_port

        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)

            print("{0}: New flow\t-\t{1}".format(self._APP_NAME, pkt))
            priority = 1000# ofproto_v1_3.OFP_DEFAULT_PRIORITY

            # verify if we have a valid buffer_id, if yes avoid to send
            # both flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._contr.add_flow(datapath, priority, match, inst,
                                     0, self._table_id_l2, msg.buffer_id)
                return
            else:
                self._contr.add_flow(datapath, priority, match, inst,
                                     0, self._table_id_l2)
                pass

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions,
                                  data=data)
        self._contr.packet_out(datapath, out)
	print "l2switch packet out src: eth_src " + eth_src + ". eth_dst " + eth_dst

    def switch_features(self, event):
        """Process a switch features event from the controller.

        :param event: The OpenFlow event.
        """
        # Install table-miss flow entry for the L2 switching flow table.
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self._contr.add_flow(datapath, 1, match, inst, 0,
                             self._table_id_l2)

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
            print("{0}: The following OpenFlow protocol events are not "
                  "supported by the controller:".format(self._APP_NAME))
            for f in failures:
                print("\t- {0}".format(f))
            return False
        else:
            return True
