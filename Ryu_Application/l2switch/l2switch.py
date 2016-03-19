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
    _TABLE_ID_L2 = 0  # Change this later!

    def __init__(self, contr):
        """Initialise the L2Switch application.

        :param contr: The controller abstraction.
        """
        self._contr = contr
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

        pkt = packet.Packet(msg.data)
        eth_head = pkt.get_protocols(ethernet.ethernet)[0]

        eth_dst = eth_head.dst
        eth_src = eth_head.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        print("{0}: Packet in\t-\tData-path ID: {1}, Source Ethernet: "
              "{2}, Destination Ethernet: {3}, Ingress switch port: {"
              "4}".format(self._APP_NAME, dpid, eth_src, eth_dst,
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
            priority = ofproto_v1_3.OFP_DEFAULT_PRIORITY

            # verify if we have a valid buffer_id, if yes avoid to send
            # both flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self._contr.add_flow(datapath, priority, match, inst,
                                     0, self._TABLE_ID_L2, msg.buffer_id)
                return
            else:
                self._contr.add_flow(datapath, priority, match, inst,
                                     0, self._TABLE_ID_L2)
                pass

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions,
                                  data=data)
        self._contr.send_msg(datapath, out)

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
        self._contr.add_flow(datapath, 0, match, inst, 0,
                             self._TABLE_ID_L2)

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
