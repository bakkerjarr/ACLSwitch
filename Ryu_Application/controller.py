# Module imports
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

from l2switch.l2switch import L2Switch

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class Controller(app_manager.RyuApp):
    """Abstracts the details of the Ryu controller.

    This class is used to provide applications with endpoints for
    modifying OpenFlow switches. Multiple Ryu applications can be
    instantiated from the controller class as a result.
    """

    _EVENT_OFP_SW_FEATURES = ofp_event.EventOFPSwitchFeatures.__name__
    _EVENT_OFP_FLOW_REMOVED = ofp_event.EventOFPFlowRemoved.__name__
    _EVENT_OFP_PACKET_IN = ofp_event.EventOFPPacketIn.__name__

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self._apps = {}
        self._handlers = {self._EVENT_OFP_SW_FEATURES: [],
                          self._EVENT_OFP_FLOW_REMOVED: [],
                          self._EVENT_OFP_PACKET_IN: []}
        self._register_app(L2Switch(self))

        self.mac_to_port = {}

    def get_ofpe_handlers(self):
        """Return the tuple of the OpenFlow protocol event handlers.

        :return: A tuple.
        """
        return self._handlers.keys()

    def _register_app(self, app_obj):
        """Register a Ryu app with the controller abstraction.

        :param app_obj: Reference to the app's Python module.
        """
        # Check that the Ryu app can be supported by the controller
        app_name = app_obj.get_app_name()
        if app_obj.is_supported() is True:
            self.logger.info("Registering Ryu app: %s", app_name)
            self._apps[app_name] = app_obj
        else:
            self.logger.error("Ryu app %s cannot be supported by the "
                              "controller.", app_name)
            return
        # Record what event handlers the Ryu app is listening for
        app_handlers = app_obj.get_expected_handlers()
        print(self._handlers)
        for handler in app_handlers:
            self._handlers[handler].append(app_name)
        print(self._handlers)

    # Methods that send data to OpenFlow switches
    def add_flow(self, datapath, priority, match, inst, time_limit,
                  table_id, buffer_id=None):
        """Reactively add a flow table entry to a switch's flow table.

        :param datapath: The switch to add the flow-table entry to.
        :param priority: Priority of the flow-table entry.
        :param match: What packet header fields should be matched.
        :param inst: The behaviour that matching flows should follow.
        :param time_limit: When the rule should expire.
        :param table_id: What flow table the flow-table entry should
        be sent to.
        :param buffer_id: Identifier of buffer queue if traffic is
        being buffered.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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
        self.send_msg(datapath, mod)

    def send_msg(self, datapath, msg):
        """Send a message to a switch such as an OFPPacketOut message.

        :param datapath: The switch to send the message to.
        :param msg: The message to send to switch specified in datapath.
        """
        datapath.send_msg(msg)

    # OpenFlow switch event handlers

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, event):
        """Catch and handle OpenFlow Protocol SwitchFeatures events.

        :param event: The OpenFlow event.
        """
        datapath_id = event.msg.datapath_id

        self.logger.info("Switch \'{0}\' connected.".format(datapath_id))

        for app in self._handlers[self._EVENT_OFP_PACKET_IN]:
            self._apps[app].switch_features(event)

        # Install table-miss flow entry for the ACL flow table. No
        # buffer is used for this table-miss entry as matching flows
        # get passed onto the L2 switching flow table.
        #match = parser.OFPMatch()
        # No action required for forwarding to another table
        #actions = None
        #self._add_flow(datapath, 0, match, actions,
        #               table_id=self._TABLE_ID_ACL)

        # Install table-miss flow entry for the L2 switching flow table.
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
         #                                 ofproto.OFPCML_NO_BUFFER)]
        #self._add_flow(datapath, 0, match, actions)

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
        print("Flow table entry removed.\n\t Flow match: {0}".format(
            match))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, event):
        """Catch and handle OpenFlow Protocol PacketIn events.

        :param event: The OpenFlow event.
        """
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if event.msg.msg_len < event.msg.total_len:
            print("{0}: Packet truncated: only {1} of {2} "
                  "bytes".format(self._APP_NAME, event.msg.msg_len,
                                 event.msg.total_len))
        for app in self._handlers[self._EVENT_OFP_PACKET_IN]:
            self._apps[app].packet_in(event)
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        #if event.msg.msg_len < event.msg.total_len:
            #self._logging.warning("Packet truncated: only {0} of {1} "
                                  #"bytes".format(event.msg.msg_len,
                                  #               event.msg.total_len))
        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        #pkt = packet.Packet(msg.data)
        #eth_head = pkt.get_protocols(ethernet.ethernet)[0]

        #eth_dst = eth_head.dst
        #eth_src = eth_head.src

        dpid = datapath.id
       # self.mac_to_port.setdefault(dpid, {})

        #self._logging.info("Packet in\t-\tData-path ID: {0}, Source "
         #                  "Ethernet: {1}, Destination Ethernet: {2}, "
          #                 "Ingress switch port: {3}".format(dpid,
           #                                                  eth_src,
            ##                                                in_port))

        # learn a mac address to avoid FLOOD next time.
        #self.mac_to_port[dpid][eth_src] = in_port

        #if eth_dst in self.mac_to_port[dpid]:
        #    out_port = self.mac_to_port[dpid][eth_dst]
        #else:
        #    out_port = ofproto.OFPP_FLOOD

        #actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        #if out_port != ofproto.OFPP_FLOOD:
        #    match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)

            #self._logging.info("New flow\t-\t{0}".format(pkt))
            #priority = ofproto_v1_3.OFP_DEFAULT_PRIORITY

            # verify if we have a valid buffer_id, if yes avoid to send
            # both flow_mod & packet_out
            #if msg.buffer_id != ofproto.OFP_NO_BUFFER:
             #   #self._add_flow(datapath, priority, match, actions,
                             #  msg.buffer_id)
              #  return
            #else:
                #self._add_flow(datapath, priority, match, actions)
#                pass

 #       data = None
  #      if msg.buffer_id == ofproto.OFP_NO_BUFFER:
   #         data = msg.data

    #    out = parser.OFPPacketOut(datapath=datapath,
     #                             buffer_id=msg.buffer_id,
      #                            in_port=in_port, actions=actions,
       #                           data=data)
        #datapath.send_msg(out)