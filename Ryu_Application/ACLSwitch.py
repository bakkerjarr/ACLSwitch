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

# ACLSwitch modules
from ACLSwitchLogging import ACLSwitchLogging

__author__ = "Jarrod N. Bakker"
__status__ = "Development"

class ACLSwitch(app_manager.RyuApp):
    """Main class for ACLSwitch. Used to create objects and listen for OpenFlow events.
    """

    def __init__(self, *args, **kwargs):
        # Create logging object first!
        self._logging = ACLSwitchLogging()
        self._logging.info("Starting ACLSwitch...")

        super(ACLSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # Create objects to manage stuff

        # TODO If one of the components fails to start then the application should terminate.
        self._logging.success("ACLSwitch started successfully.")


    # OpenFlow switch event handlers

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, event):
        """Catch and handle OFPSwitchFeatures events.

        :param event: The OpenFlow event
        """
        datapath = event.msg.datapath
        datapath_id = event.msg.datapath_id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self._logging.info("Switch \'{0}\' connected.".format(
                datapath_id))

    @set_ev_cls(ofp_event.EventOFPFlowRemoved)
    def _flow_removed_handler(self, ev):
        """Catch and handle OFPFlowRemoved events.

        :param event: The OpenFlow event
        """
        msg = ev.msg
        match = msg.match
        print("[?] Flow table entry removed.\n\t Flow match: "
              + str(match))
