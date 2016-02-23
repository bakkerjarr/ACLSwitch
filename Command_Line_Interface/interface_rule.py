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
###########################################################################
# An interactive command-line based interface for rule management of the
# Stateless SDN Firewall application.
#
# The interface will perform syntax checking on the input before sending
# it to ACLSwitch.
#
# Note that this application must be run on the controller itself.
#
# This file contains the logic for adding and removing rules from the ACL
# within ACLSwitch.
#
# Author: Jarrod N. Bakker
#

# Libraries
from datetime import datetime
import json
import requests
import rule_syntax

TABLE_ID_BLACKLIST = 0
TABLE_ID_WHITELIST = 1
TABLE_ID_L2 = 2


class ACLInterfaceRule:

    # Constants
    PROMPT_RULE = "ACL Switch (rule) > "
    PROMPT_RULE_ADD = "ACL Switch (rule -> add) > "
    PROMPT_RULE_REMOVE = "ACL Switch (rule -> remove) > "
    PROMPT_RULE_TIME = "ACL Switch (rule -> time) > "
    PROMPT_RULE_LIST = "ACLE Switch (rule -> dst_list) > "
    TEXT_ERROR_SYNTAX = ("ERROR: Incorrect syntax, could not process"
                        "  given command.")
    TEXT_ERROR_SYNTAX_TIME_START = ("ERROR: Incorrect syntax, given"
                                   " time was not recognised.")
    TEXT_ERROR_SYNTAX_TIME_DURATION = ("ERROR: Incorrect syntax, given"
                                      " duration not between 1-1092min.")
    TEXT_ERROR_CONNECTION = ("ERROR: Unable to establish a connection"
                            "  with ACLSwitch.")
    TEXT_HELP_RULE = "\tadd, remove, rule_list OR time"
    TEXT_HELP_RULE_ADD = ("\tRule to add: ip_src ip_dst transport_protocol"
                         " port_src port_dst policy")
    TEXT_HELP_RULE_REMOVE = "\tRule to remove: rule_id"
    TEXT_HELP_RULE_TIME = ("\tRule to add: ip_src ip_dst transport_protocol"
                          " port_src port_dst policy time_start(e.g. 13:45)"
                          " duration(mins)")
    TEX_HELP_RULE_LIST = ("\tRule to add: ip_src ip_dst transport_protocol"
                         " port_src port_dst policy rule_dst_list")
    TIME_MAX_MINUTES = 1092
    TIME_MIN_MINUTES = 1
    URL_ACLSWITCH_RULE = "http://127.0.0.1:8080/acl_switch/acl_rules" # using loopback
    URL_ACLSWITCH_TIME = "http://127.0.0.1:8080/acl_switch/acl_rules/time" # using loopback

    """
    Add interface. In this 'mode' the user is invited to input fields for an
    ACL rule. The rule is passed to ACLSwitch using a REST API as a JSON
    object.
    """
    def __init__(self):
        print self.TEXT_HELP_RULE
        buf_in = raw_input(self.PROMPT_RULE)
        if buf_in == "add":
            self.rule_add()
        elif buf_in == "remove":
            self.rule_remove()
        elif buf_in == "time":
            self.rule_time()
        elif buf_in == "rule_list":
            self.rule_dst_list()
        else:
            print(self.TEXT_ERROR_SYNTAX + "\n" + self.TEXT_HELP_RULE) # syntax error
            
    """
    Convert rule fields into a JSON object for transmission.
    
    @param ip_src - source IP address to be encoded
    @param ip_dst - destination IP address to be encoded
    @param tp_proto - transport layer (layer 4) protocol to be encoded
    @param port_src - source port number to be encoded
    @param port_dst - destination port number to be encoded
    @param policy - policy to be encoded
    @return - JSON representation of the rule
    """
    def rule_to_json(self, ip_src, ip_dst, tp_proto, port_src, port_dst, policy, dst_list = TABLE_ID_BLACKLIST):
       rule_dict = {}
       rule_dict["ip_src"] = ip_src
       rule_dict["ip_dst"] = ip_dst
       rule_dict["tp_proto"] = tp_proto
       rule_dict["port_src"] = port_src
       rule_dict["port_dst"] = port_dst
       rule_dict["policy"] = policy
       rule_dict["dst_list"] = dst_list
       print("rule_to_json")
       return json.dumps(rule_dict)

    def rule_dst_list(self):
        print self.TEX_HELP_RULE_LIST
        buf_in = raw_input(self.PROMPT_RULE_LIST)
        items = buf_in.split(" ")

        if len(items) != 7:
            print "Expected 7 arguments, " + str(len(items)) + " given."
            return
        items[2] = items[2].lower()
        errors = rule_syntax.check_rule(items[0], items[1], items[2],
                                        items[3], items[4])
        DSTLIST = 0
        if (items[6] == "whitelist"):
            items[6] = TABLE_ID_WHITELIST
        elif (items[6] == "blacklist"):
            items[6] = TABLE_ID_BLACKLIST
        else:
            print("Invalid list specified")

        if len(errors) != 0 :
            print "Invalid rule provided:"
            for e in errors:
                print "\t" + e
            return
        add_req = self.rule_to_json(items[0], items[1], items[2],
                                    items[3], items[4], items[5],
                                    items[6])
        try:
            resp = requests.post(self.URL_ACLSWITCH_RULE, data=add_req,
                                headers = {"Content-type": "application/json"})
            print("adding request with rule destination list" + add_req)
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error creating resource, HTTP " + str(resp.status_code))
        print resp.text

    """
    The user is invited to input fields for an ACL rule. The rule is
    passed to ACLSwitch using a REST API as a JSON object.
    """
    def rule_add(self):
        print self.TEXT_HELP_RULE_ADD
        buf_in = raw_input(self.PROMPT_RULE_ADD)
        items = buf_in.split(" ")

        if len(items) != 6:
            print "Expected 6 arguments, " + str(len(items)) + " given."
            return
        items[2] = items[2].lower()
        errors = rule_syntax.check_rule(items[0], items[1], items[2],
                                        items[3], items[4])
        if len(errors) != 0 :
            print "Invalid rule provided:"
            for e in errors:
                print "\t" + e
            return
        add_req = self.rule_to_json(items[0], items[1], items[2],
                                    items[3], items[4], items[5])
        try:
            resp = requests.post(self.URL_ACLSWITCH_RULE, data=add_req,
                                headers = {"Content-type": "application/json"})
            print("adding request" + add_req)
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error creating resource, HTTP " + str(resp.status_code))
        print resp.text

    """
    The user is invited to input the ID of an ACL rule to be deleted.
    The ID is passed to ACLSwitch using a REST API as a JSON object.
    """
    def rule_remove(self):
        print self.TEXT_HELP_RULE_REMOVE
        buf_in = raw_input(self.PROMPT_RULE_REMOVE)
        try:
            int(buf_in)
            if int(buf_in) < 0:
                print "Rule id should be a positive integer."
                return
        except:
            print "Rule id should be a positive integer."
            return
        delete_req = json.dumps({"rule_id": buf_in})
        try:
            resp = requests.delete(self.URL_ACLSWITCH_RULE, data=delete_req,
                                   headers = {"Content-type": "application/json"})
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error deleting resource, HTTP " + str(resp.status_code))
        print resp.text
    """
    Convert a time-based rule fields into a JSON object for transmission.
    
    @param ip_src - source IP address to be encoded
    @param ip_dst - destination IP address to be encoded
    @param tp_proto - transport layer (layer 4) protocol to be encoded
    @param port_src - source port number to be encoded
    @param port_dst - destination port number to be encoded
    @param policy - policy to be encoded
    @param time_start - start time to be encoded
    @param time_duration - time duration to be encoded
    @return - JSON representation of the rule
    """
    def rule_time_to_json(self, ip_src, ip_dst, tp_proto, port_src,
                          port_dst, policy, time_start, time_duration):
       rule_dict = {}
       rule_dict["ip_src"] = ip_src
       rule_dict["ip_dst"] = ip_dst
       rule_dict["tp_proto"] = tp_proto
       rule_dict["port_src"] = port_src
       rule_dict["port_dst"] = port_dst
       rule_dict["policy"] = policy
       rule_dict["time_start"] = time_start
       rule_dict["time_duration"] = time_duration
       return json.dumps(rule_dict)

    """
    The user is invited to input fields for an ACL rule that is enforced
    for a specific time period within a day. The rule is passed to
    ACLSwitch using a REST API as a JSON object.
    """
    def rule_time(self):
        print self.TEXT_HELP_RULE_TIME
        buf_in = raw_input(self.PROMPT_RULE_TIME)
        items = buf_in.split(" ")
        if len(items) != 8:
            print "Expected 8 arguments, " + str(len(items)) + " given."
            return
        items[2] = items[2].lower()
        errors = rule_syntax.check_rule(items[0], items[1], items[2],
                                        items[3], items[4])
        if len(errors) != 0 :
            print "Invalid rule provided:"
            for e in errors:
                print "\t" + e
            return
        # Check that the given time is valid
        try:
            datetime.strptime(items[6], "%H:%M")
        except:
            print self.TEXT_ERROR_SYNTAX_TIME_START        
            return
        # Check that the duration for the rule is valid
        try:
            duration = int(items[7])
            if (duration > self.TIME_MAX_MINUTES
                or duration < self.TIME_MIN_MINUTES):
                raise
        except:
            print self.TEXT_ERROR_SYNTAX_TIME_DURATION
            return
        add_req = self.rule_time_to_json(items[0], items[1], items[2],
                                         items[3], items[4], items[5],
                                         items[6], str(duration*60))
        try:
            resp = requests.post(self.URL_ACLSWITCH_TIME, data=add_req,
                                headers = {"Content-type": "application/json"})
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error creating resource, HTTP " + str(resp.status_code))
        print resp.text

