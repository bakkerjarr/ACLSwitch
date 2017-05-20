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

# Ryu and OpenFlow modules
from ryu.app.ofctl import api
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.controller import dpset

# Application modules
from l2switch.l2switch import L2Switch
from aclswitch.aclswitch import ACLSwitch

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class Controller(dpset.DPSet):
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

    def add_flow(self, datapath, priority, match, inst, hard_timeout,
                  table_id, buffer_id=None, in_port=None, msg=None, idle_timeout=0, packet_out=True, cookie=0):
        """Reactively add a flow table entry to a switch's flow table.

        :param datapath: The switch to add the flow-table entry to.
        :param priority: Priority of the flow-table entry.
        :param match: What packet header fields should be matched.
        :param inst: The behaviour that matching flows should follow.
        :param hard_timeout: When the rule should expire.
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
                                    hard_timeout=0,
                                    idle_timeout=idle_timeout,
                                    priority=priority, match=match,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    instructions=inst, table_id=table_id, cookie=cookie)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    hard_timeout=0,
                                    idle_timeout=idle_timeout,
                                    priority=priority, match=match,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    instructions=inst, table_id=table_id, cookie=cookie)
        self._send_msg(datapath, mod)
        if packet_out:
            if msg:
                out = None
                if buffer_id and buffer_id != 0xffffffff:
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        actions=[parser.OFPActionOutput(ofproto.OFPP_TABLE)],
                        in_port=in_port,
                        buffer_id=buffer_id,
                        data=msg.data)
                    datapath.send_msg(out)
                else:
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        actions=[parser.OFPActionOutput(ofproto.OFPP_TABLE)],
                        in_port=in_port,
                        buffer_id=0xffffffff,
                        data=msg.data)
                    datapath.send_msg(out)

    def remove_flow(self, datapath, parser, table, remove_type, priority,
                    match, out_port, out_group, cookie=0, cookie_mask=0):
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
                                out_group=out_group,
                                cookie=cookie, cookie_mask=cookie_mask)
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
        datapath = event.msg.datapath
        ofproto = event.msg.datapath.ofproto
        parser = event.msg.datapath.ofproto_parser
        self.logger.info("Switch \'{0}\' connected.".format(datapath_id))


        mod = parser.OFPFlowMod(datapath=datapath, table_id=ofproto.OFPTT_ALL,
                                command=ofproto.OFPFC_DELETE, priority=0,
                                match=parser.OFPMatch(), out_port=ofproto.OFPP_ANY, 
                                out_group=ofproto.OFPG_ANY,
                                cookie=0, cookie_mask=0,
                                buffer_id=0xffffffff)

        datapath.send_msg(mod)

        self.logger.info("Switch \'{0}\' all tables cleared.".format(datapath_id)
)
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
        self.logger.info("Cookie: %x", msg.cookie)
                         
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
            
    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg

        self.logger.warning('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s',
                          msg.type, msg.code, msg.data)
   
   
    @set_ev_cls(ofp_event.EventOFPTableFeaturesStatsReply, MAIN_DISPATCHER)
    def h(self, ev):
        print "table features stats reply"
        print ev.msg
    
    
    
