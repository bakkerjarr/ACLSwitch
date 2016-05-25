# Ryu and OpenFlow modules
from ryu.app.ofctl import api
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

# Application modules
from l2switch.l2switch import L2Switch
from aclswitch.aclswitch import ACLSwitch

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class Controller(app_manager.RyuApp):
    """Abstracts the details of the Ryu controller.

    This class is used to provide applications with endpoints for
    modifying OpenFlow switches. Multiple Ryu applications can be
    instantiated from the controller class as a result.
    """

    _CONTEXTS = {"wsgi": WSGIApplication}
    _EVENT_OFP_SW_FEATURES = ofp_event.EventOFPSwitchFeatures.__name__
    _EVENT_OFP_FLOW_REMOVED = ofp_event.EventOFPFlowRemoved.__name__
    _EVENT_OFP_PACKET_IN = ofp_event.EventOFPPacketIn.__name__
    _INSTANCE_NAME_CONTR = "ryu_controller_abstraction"

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self._apps = {}
        self._handlers = {self._EVENT_OFP_SW_FEATURES: [],
                          self._EVENT_OFP_FLOW_REMOVED: [],
                          self._EVENT_OFP_PACKET_IN: []}
        self._wsgi = kwargs['wsgi']
        # Insert Ryu applications below
        self._register_app(L2Switch(self))
        self._register_app(ACLSwitch(self))

    def get_ofpe_handlers(self):
        """Return the tuple of the OpenFlow protocol event handlers.

        :return: A tuple.
        """
        return self._handlers.keys()

    def register_rest_wsgi(self, rest_wsgi, **kwargs):
        """Register a WSGI with Ryu.

        :param rest_wsgi: The WSGI to register.
        :return: True is successful, False otherwise.
        """
        all_kwargs = kwargs["kwargs"].copy()
        all_kwargs[self._INSTANCE_NAME_CONTR] = self
        self._wsgi.register(rest_wsgi, all_kwargs)
        return True

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
        for handler in app_handlers:
            self._handlers[handler].append(app_name)

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
        self._send_msg(datapath, mod)

    def remove_flow(self, datapath, parser, table, remove_type, priority,
                    match, out_port, out_group):
        """Remove a flow table entry from a switch.

        The callee should decide of the removal type.

        :param datapath: The switch to remove the flow from.
        :param parser: Parser for the OpenFlow switch.
        :param table: Table id to send the flow mod to.
        :param remove_type: OFPFC_DELETE or OFPFC_DELETE_STRICT.
        :param priority: Priority of the flow table entry.
        :param match: What packet header fields should be matched.
        :param out_port: Switch port to match.
        :param out_group: Switch group to match.
        """
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table,
                                command=remove_type, priority=priority,
                                match=match, out_port=out_port,
                                out_group=out_group)
        datapath.send_msg(mod)

    def packet_out(self, datapath, out):
        """Send a packet out message to a switch.

        :param datapath: The switch to send the message to.
        :param out: The packet out message.
        """
        self._send_msg(datapath, out)

    def _send_msg(self, datapath, msg):
        """Send a message to a switch such as an OFPPacketOut message.

        :param datapath: The switch to send the message to.
        :param msg: The message to send to switch specified in datapath.
        """
        datapath.send_msg(msg)

    # Misc.
    def switch_get_datapath(self, datapath_id):
        """Return a datapath object given its datapath ID.

        :param datapath_id: ID of a datapath i.e. switch ID.
        :return: Datapath object.
        """
        return api.get_datapath(self, datapath_id)

    # OpenFlow switch event handlers

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, event):
        """Catch and handle OpenFlow Protocol SwitchFeatures events.

        :param event: The OpenFlow event.
        """
        datapath_id = event.msg.datapath_id

        self.logger.info("Switch \'{0}\' connected.".format(datapath_id))

        for app in self._handlers[self._EVENT_OFP_SW_FEATURES]:
            self._apps[app].switch_features(event)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved)
    def _flow_removed_handler(self, event):
        """Catch and handle OpenFlow Protocol FlowRemoved events.

        :param event: The OpenFlow event.
        """
        msg = event.msg
        match = msg.match
        self.logger.info("Flow table entry removed.\n\t Flow match: {"
                         "0}".format(match))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, event):
        """Catch and handle OpenFlow Protocol PacketIn events.

        :param event: The OpenFlow event.
        """
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if event.msg.msg_len < event.msg.total_len:
            self.logger.warning("Packet truncated: only {0} of {1} "
                                "bytes".format(event.msg.msg_len,
                                               event.msg.total_len))
        for app in self._handlers[self._EVENT_OFP_PACKET_IN]:
            self._apps[app].packet_in(event)
