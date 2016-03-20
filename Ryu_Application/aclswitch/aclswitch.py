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

# ACLSwitch modules
from abc_ryu_app import ABCRyuApp
from acl.acl_manager import ACLManager
from aclswitch_api import ACLSwitchAPI
from aclswitch_logging import ACLSwitchLogging

# Other modules
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
        self._acl_man = ACLManager(self._logging)
        self._api = ACLSwitchAPI(self._logging, self._acl_man)

        # Read config file
        # TODO Command line argument for custom location for config file
        file_loc = (os.path.dirname(__file__) + "/" +
                    self._CONFIG_FILE_NAME)
        self._import_config_file(file_loc)

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
                    result = self._api.create_acl_rule(config["rule"])
                    if result[0] is True:
                        self._logging.success("Rule created: {"
                                              "0}".format(config[
                                                                "rule"]))
                    else:
                        self._logging.fail("Rule creation failed: {"
                                           "0}".format(result[1]))
                elif "policy" in config:
                    self._logging.info("Parsing policy domain: {"
                                       "0}".format(config["policy"]))
                else:
                    self._logging.fail(line + "is not recognised JSON.")
            buf_in.close()
        except IOError:
            self._logging.fail("Unable to read from file: " +
                               str(file_loc))

    def switch_features(self, event):
        """Process a switch features event from the controller.

        :param event: The OpenFlow event.
        """
        datapath = event.msg.datapath
        datapath_id = event.msg.datapath_id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry for the ACL flow table. No
        # buffer is used for this table-miss entry as matching flows
        # get passed onto the L2 switching flow table.
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(self._TABLE_ID_L2)]
        self._contr.add_flow(datapath, 0, match, inst, 0,
                             self._TABLE_ID_ACL)

        # Take note of switches (via their datapaths)
        # TODO Activate the following once policy domains have been implemented.
        #dp_id = ev.msg.datapath_id
        #self._connected_switches[dp_id] = [self.POLICY_DEFAULT]

        # Distribute the list of rules to the switch
        #self._distribute_rules_policy_set(datapath, self.POLICY_DEFAULT)

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
