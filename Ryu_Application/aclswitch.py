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
##########################################################################
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
####################################################################
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
#####################################################################

# Modules
# Ryu and OpenFlow protocol
from ryu.app.ofctl import api
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser as ofp13_parser
# Packets
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from netaddr import IPAddress  # TODO Use ryu packet instead of netaddr
# REST interface
from ryu.app.wsgi import WSGIApplication
import acl_switch_rest
# Other
from collections import namedtuple
from ryu.lib import hub
import datetime as dt
import json
import rule_syntax
import sys
import os

# Global field needed for REST linkage
acl_switch_instance_name = "acl_switch_app"


class ACLSwitch(app_manager.RyuApp):
    # Constants
    ACL_ENTRY = namedtuple("ACL_ENTRY",
                           "ip_src ip_dst tp_proto port_src "
                           "port_dst policy time_start time_duration")
    CONFIG_FILENAME = "/home/ubuntu/ACLSwitch/Ryu_Application/config.json"

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    OFP_MAX_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY * 2 - 1
    # Default priority is defined to be in the middle (0x8000 in 1.3)
    # Note that for a priority p, 0 <= p <= MAX (i.e. 65535)
    POLICY_DEFAULT = "default"

    TABLE_ID_ACL = 0
    TABLE_ID_L2 = 1
    TABLE_ID_BLACKLIST = 2
    TABLE_ID_WHITELIST = 3

    TIME_PAUSE = 1  # In seconds

    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(ACLSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # Initialise instance variables
        self._access_control_list = {}  # rule_id:ACL_ENTRY
        self._acl_id_count = 0
        self._connected_switches = {}  # dpip:[policy]
        self._policy_to_rules = {}  # policy:[rules]
        self._rule_time_queue = []
        self._gthread_rule_dist = None

        # Create the default polciy
        self.policy_create(self.POLICY_DEFAULT)

        # Import config from file
        try:
            self._import_from_file(self.CONFIG_FILENAME)
            print("[!] Config loaded.")
        except:
            print("[-] ERROR: could not read from file \'"
                  + str(self.CONFIG_FILENAME) + "\'")
            print("[!] No config loaded.")

        # Create an object for the REST interface
        wsgi = kwargs['wsgi']
        wsgi.register(acl_switch_rest.ACLSwitchREST,
                      {acl_switch_instance_name: self})

    """
    Read in ACL rules from file filename. Note that the values passed
    through will have 'u' in front of them. This denotes that the string
    is Unicode encoded, as such it will affect the intended value.

    @param filename - the input file
    """

    def _import_from_file(self, filename):
        buf_in = open(filename)
        print("[?] Reading from file \'" + str(filename) + "\'")
        for line in buf_in:
            if line[0] == "#" or not line.strip():
                continue  # Skip file comments and empty lines
            try:
                config = json.loads(line)
            except:
                print("[-] Line: " + line + "is not valid JSON.")
                continue
            if "rule" in config:
                rule = config["rule"]
                self.acl_rule_add(rule["ip_src"], rule["ip_dst"],
                                  rule["tp_proto"], rule["port_src"],
                                  rule["port_dst"], rule["policy"])
            elif "policy" in config:
                self.policy_create(config["policy"])
            elif "rule_time" in config:
                rule = config["rule_time"]
                self.acl_rule_add(rule["ip_src"], rule["ip_dst"],
                                  rule["tp_proto"], rule["port_src"],
                                  rule["port_dst"], rule["policy"],
                                  rule["time_start"],
                                  rule["time_duration"])
            else:
                print("[-] Line: " + line + "is not recognised JSON.")
        buf_in.close()

        # Methods used for fetching information on the current state of
        # ACLSwitch.

    """
    Compile and return information on ACLSwitch. The information is
    comprised of the number of policies, the number of ACL rules, the
    number of switches and the current time of the machine that this
    application is running on. This should only be taken as an
    approximation of the current time therefore the time should only
    be accurate within minutes.

    @return - a dictionary containing information on the ACLSwitch.
    """

    def get_info(self):
        num_policies = str(len(self._policy_to_rules))
        num_rules = str(len(self._access_control_list))
        num_switches = str(len(self._connected_switches))
        controller_time = dt.datetime.now().strftime("%H:%M")
        return {"num_policies": num_policies, "num_rules": num_rules,
                "num_switches": num_switches,
                "controller_time": controller_time}

    """
    Return a list of the currently available policies.

    @return - a list of the currently available policies.
    """

    def get_policy_list(self):
        return self._policy_to_rules.keys()

    """
    Return the ACL as a formatted dict.

    @return - a formatted dict representing the ACL.
    """

    def get_acl(self):
        acl_formatted = {}
        for rule_id in self._access_control_list:
            rule = self._access_control_list[rule_id]
            # Order the list as it's created by using rule_id
            acl_formatted[int(rule_id)] = {"rule_id": rule_id,
                                           "ip_src": rule.ip_src,
                                           "ip_dst": rule.ip_dst,
                                           "tp_proto": rule.tp_proto,
                                           "port_src": rule.port_src,
                                           "port_dst": rule.port_dst,
                                           "policy": rule.policy,
                                           "time_start": rule.time_start,
                                           "time_duration": rule.time_duration}
        return acl_formatted

    """
    Return a dict of the currently connected switches and their
    associated policies.

    @return - a dict of the currently connected switches and the
              policies associated with them.
    """

    def get_switches(self):
        return self._connected_switches

    """
    Return a list of the time constrained rules mapped to their
    scheduled times. I.e. [["HH:MM","<rule id>","<rule_id>",...],...]

    @return - a list representing the time constrained rules mapped to
              their times.
    """

    def get_time_queue(self):
        queue_formatted = []
        for time_period in self._rule_time_queue:
            time_formatted = []
            time = self._access_control_list[time_period[0]].time_start
            time_formatted.append(time)
            time_formatted.extend(time_period)
            queue_formatted.append(time_formatted)
        return queue_formatted

    # Methods handling the management of switch policies

    """
    Create a policy which can then be assigned to a switch.

    @param new_policy - name of the policy to create.
    @return - result of the operation along with a message.
    """

    def policy_create(self, new_policy):
        if new_policy in self._policy_to_rules:
            return (False, "Policy " + new_policy + " already exists.")
        self._policy_to_rules[new_policy] = []
        print("[+] New policy added: " + new_policy)
        return (True, "Policy " + new_policy + " created.")

    """
    Delete a policy. This can only be done once there are no rules
    associated with the policy.

    @param policy - name of the policy to delete.
    @return - result of the operation along with a message.
    """

    def policy_delete(self, policy):
        if policy == self.POLICY_DEFAULT:
            return (False, "Policy \'default\' cannot be deleted.")
        if policy not in self._policy_to_rules:
            return (False, "Policy " + policy + " does not exist.")
        if self._policy_to_rules[policy]:
            return (False, "Cannot delete policy " + policy +
                    ", rules are still assoicated with it.")
        for switch in self._connected_switches:
            if policy in self._connected_switches[switch]:
                return (False, "Cannot delete policy " + policy +
                        ", switches still have it assigned.")
        del self._policy_to_rules[policy]
        print("[+] Policy deleted: " + policy)
        return (True, "Policy " + policy + " deleted.")

    """
    Assign a policy to a switch then give it the appropriate rules.

    @param switch_id - the datapath_id of a switch, switch_id is used
                       for consistency with the API.
    @param policy - the new policy to assign to a switch.
    @return - result of the operation along with a message.
    """

    def policy_switch_assign(self, switch_id, new_policy):
        if new_policy not in self._policy_to_rules:
            return (False, "Policy " + new_policy + " does not exist.")
        if switch_id not in self._connected_switches:
            return (
            False, "Switch " + str(switch_id) + " does not exist.")
        if new_policy in self._connected_switches[switch_id]:
            return (
            False, "Switch " + str(switch_id) + " already has policy "
            + str(new_policy) + ".")
        self._connected_switches[switch_id].append(new_policy)
        datapath = api.get_datapath(self, switch_id)
        self._distribute_rules_policy_set(datapath, new_policy)
        print("[+] Switch " + str(
            switch_id) + " assigned policy: " + new_policy)
        return (True, "Switch " + str(switch_id) + " given policy "
                + new_policy + ".")

    """
    Remove a policy assignment from a switch then remove the respective
    rules from the switch. Assumes that once the policy has been removed
    the respective rules will be successfully removed from the switches.

    @param switch_id - the datapath_id of a switch, switch_id is used
                       for consistency with the API.
    @param old_policy - the policy to remove from a switch.
    @return - result of the operation along with a message.
    """

    def policy_switch_remove(self, switch_id, old_policy):
        if old_policy not in self._policy_to_rules:
            return (False, "policy " + old_policy + " does not exist.")
        if switch_id not in self._connected_switches:
            return (False, "Switch " + str(switch_id) + " does not "
                                                        "exist.")
        if old_policy not in self._connected_switches[switch_id]:
            return (False,
                    "Switch " + str(switch_id) + " does not have "
                                                 "policy " + str(
                        old_policy) + ".")
        self._connected_switches[switch_id].remove(old_policy)
        datapath = api.get_datapath(self, switch_id)
        for rule_id in self._policy_to_rules[old_policy]:
            rule = self._access_control_list[rule_id]
            match = self._create_match(rule)
            self._delete_flow(datapath, self.OFP_MAX_PRIORITY, match)
        print("[+] Switch " + str(
            switch_id) + " removed policy: " + old_policy)
        return (True, "Switch " + str(switch_id) + " had policy " +
                old_policy + " removed.")

    # Methods handling the use of the ACL

    """
    Return the IP version being used given the source and destination
    addresses.

    @param ip_src - the source IP address to check.
    @param ip_dst - the destination IP address to check.
    @return - the IP version being used.
    """

    def _return_ip_version(self, ip_src, ip_dst):
        if "*" not in ip_src:
            return IPAddress(ip_src).version
        else:
            return IPAddress(ip_dst).version

    """
    Create an OFPMatch instance based on the contents of an ACL_ENTRY.

    @param rule - the entry to create an OFPMatch instance from
    @return - the OFPMatch instance
    """

    def _create_match(self, rule):
        match = ofp13_parser.OFPMatch()
        ip_version = self._return_ip_version(rule.ip_src, rule.ip_dst)
        # Match IP layer (layer 3)
        if ip_version == 4:
            # Match IPv4
            match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,
                               ethernet.ether.ETH_TYPE_IP)
            if rule.ip_src != "*":
                match.append_field(ofproto_v1_3.OXM_OF_IPV4_SRC,
                                   int(IPAddress(rule.ip_src)))
            if rule.ip_dst != "*":
                match.append_field(ofproto_v1_3.OXM_OF_IPV4_DST,
                                   int(IPAddress(rule.ip_dst)))
        else:
            # Match IPv6
            match.append_field(ofproto_v1_3.OXM_OF_ETH_TYPE,
                               ethernet.ether.ETH_TYPE_IPV6)
            if rule.ip_src != "*":
                match.append_field(ofproto_v1_3.OXM_OF_IPV6_SRC,
                                   IPAddress(rule.ip_src).words)
            if rule.ip_dst != "*":
                match.append_field(ofproto_v1_3.OXM_OF_IPV6_DST,
                                   IPAddress(rule.ip_dst).words)

        # Match transport layer (layer 4)
        if rule.tp_proto != "*":
            if rule.tp_proto == "tcp":
                # Match TCP
                match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                   ipv4.inet.IPPROTO_TCP)  # covers IPv6
                if rule.port_src != "*":
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_SRC,
                                       int(rule.port_src))
                if rule.port_dst != "*":
                    match.append_field(ofproto_v1_3.OXM_OF_TCP_DST,
                                       int(rule.port_dst))
            elif rule.tp_proto == "udp":
                # Match UDP
                match.append_field(ofproto_v1_3.OXM_OF_IP_PROTO,
                                   ipv4.inet.IPPROTO_UDP)  # covers IPv6
                if rule.port_src != "*":
                    match.append_field(ofproto_v1_3.OXM_OF_UDP_SRC,
                                       int(rule.port_src))
                if rule.port_dst != "*":
                    match.append_field(ofproto_v1_3.OXM_OF_UDP_DST,
                                       int(rule.port_dst))
        return match

    """
    Returns a string representation of an IP address.

    @param ip_addr - the IP address to turn into a string.
    @return - the string representation of an IP address.
    """

    def _ip_to_string(self, ip_addr):
        if ip_addr == "*":
            return ip_addr
        return str(IPAddress(ip_addr))

    """
    Compare the 5-tuple entries of two ACL rules. That is compare the
    IP addresses, transport-layer protocol and port numbers.

    @param rule_1 - a rule to be compared.
    @param rule_2 - a rule to be compared.
    @return - True is equal, False otherwise.
    """

    def _compare_acl_rules(self, rule_1, rule_2):
        return ((self._ip_to_string(rule_1.ip_src) == self._ip_to_string(
            rule_2.ip_src)) and
                (self._ip_to_string(rule_1.ip_dst) == self._ip_to_string(
                    rule_2.ip_dst)) and
                (rule_1.tp_proto == rule_2.tp_proto) and
                (rule_1.port_src == rule_2.port_src) and
                (rule_1.port_dst == rule_2.port_dst))

    """
    Perform a syntax check off ACL rule.

    @param ip_src - the source IP address to match.
    @param ip_dst - the destination IP address to match.
    @param tp_proto - the Transport Layer (layer 4) protocol to match.
    @param port_src - the Transport Layer source port to match.
    @param port_dst - the Transport Layer destination port to match.
    @return - a tuple indicating if the operation was a success and a
              message to be returned to the client.
    """

    def _acl_rule_syntax_check(self, ip_src, ip_dst, tp_proto,
                               port_src, port_dst):
        errors = rule_syntax.check_rule(ip_src, ip_dst, tp_proto,
                                        port_src, port_dst)
        error_msg = "Provided rule has invalid syntax:"
        if len(errors) != 0:
            for e in errors:
                error_msg = error_msg + "\n\t" + e
            return (False, error_msg)
        return (True, "Rule syntax is valid.")

    """
    Add a rule to the ACL by creating an entry then appending it to the
    list.

    @param ip_src - the source IP address to match.
    @param ip_dst - the destination IP address to match.
    @param tp_proto - the Transport Layer (layer 4) protocol to match.
    @param port_src - the Transport Layer source port to match.
    @param port_dst - the Transport Layer destination port to match.
    @param policy - the policy the rule should be associated with.
    @param time_start - when the rule should start being enforced.
    @param time_duration - how long the rule should be enforced for.
    @return - a tuple indicating if the operation was a success, a message
              to be returned to the client and the new created rule. This
              is useful in the case where a single rule has been created
              and needs to be distributed among switches.
    """

    def acl_rule_add(self, ip_src, ip_dst, tp_proto, port_src, port_dst,
                     policy, time_start="N/A", time_duration="N/A"):
        syntax_results = self._acl_rule_syntax_check(ip_src, ip_dst,
                                                     tp_proto, port_src,
                                                     port_dst)
        if not syntax_results[0]:
            print("[-] " + syntax_results[1])
            return (False, syntax_results[1], None)

        if policy not in self._policy_to_rules:
            print("[-] Policy \'" + policy + "\' was not recognised.")
            return (
            False, "Policy \'" + policy + "\' was not recognised.", None)

        rule_id = str(self._acl_id_count)
        new_rule = self.ACL_ENTRY(ip_src=ip_src, ip_dst=ip_dst,
                                  tp_proto=tp_proto, port_src=port_src,
                                  port_dst=port_dst, policy=policy,
                                  time_start=time_start,
                                  time_duration=time_duration)
        for rule in self._access_control_list.values():
            if self._compare_acl_rules(new_rule, rule):
                return (False, "New rule was not created, it already "
                               "exists.", None)
        self._acl_id_count += 1  # need to update to keep ids unique
        self._access_control_list[rule_id] = new_rule
        self._policy_to_rules[policy].append(rule_id)
        if time_start != "N/A":
            self._add_to_queue(rule_id)  # schedule the rule in the queue
        else:
            self._distribute_single_rule(new_rule)
        print("[+] Rule " + str(new_rule) + " created with id: "
              + str(rule_id))
        return (True, "Rule was created with id: " + str(rule_id) + ".")

    """
    Remove a rule from the ACL then remove the associated flow table
    entries from the appropriate switches.

    @param rule_id - id of the rule to be removed.
    @return - a tuple indicating if the operation was a success and a
              message to be returned to the client.
    """

    def acl_rule_delete(self, rule_id):
        if rule_id not in self._access_control_list:
            return (False, "Invalid rule id given: " + rule_id + ".")
        # The user passed through a valid rule_id so we can proceed
        rule = self._access_control_list[rule_id]
        del self._access_control_list[rule_id]
        self._policy_to_rules[rule.policy].remove(rule_id)
        # The rule had time enforcement, it must be removed from the queue
        if rule.time_start != "N/A":
            self._remove_from_queue(rule_id)

        # Send off delete flow messages to switches that hold the rule
        for switch in self._connected_switches:
            if rule.policy not in self._connected_switches[switch]:
                continue
            match = self._create_match(rule)
            datapath = api.get_datapath(self, switch)
            self._delete_flow(datapath, self.OFP_MAX_PRIORITY, match)
        print("[+] Rule " + str(rule) + " with id: " + str(rule_id)
              + " removed.")
        return (True, "Rule with id \'" + rule_id + "\' was deleted.")

    # Methods handling the adding and removal of rules to and from
    # the queue.

    """
    Insert the ID of a time constrained rule into an ordered queue.
    When adding the rule it is necessary to check current time of day
    and the times of other rules within the queue.

    @param new_rule_id - ID of the rule which needs to be scheduled.
    """

    def _add_to_queue(self, new_rule_id):
        if len(self._rule_time_queue) < 1:
            # Queue is empty so just insert the rule and leave
            self._rule_time_queue.append([new_rule_id])
            # Start a green thread to distribute time-based rules
            self._gthread_rule_dist = hub.spawn(
                self._distribute_rules_time)
            return

        queue_head_id = self._rule_time_queue[0][0]
        queue_head_rule = self._access_control_list[queue_head_id]
        queue_head_time = dt.datetime.strptime(
            queue_head_rule.time_start,
            "%H:%M")
        new_rule = self._access_control_list[new_rule_id]
        new_rule_time = dt.datetime.strptime(new_rule.time_start,
                                             "%H:%M")

        # Get the current time and normalise it
        cur_time = dt.datetime.strptime(
            dt.datetime.now().strftime("%H:%M"),
            "%H:%M")

        # Check if the queue head needs to be pre-empted
        if ((
                        cur_time < queue_head_time and new_rule_time < queue_head_time
            and new_rule_time > cur_time) or
                (
                            cur_time > queue_head_time and cur_time < new_rule_time and
                        new_rule_time > cur_time) or
                (
                            new_rule_time < queue_head_time and cur_time > new_rule_time and
                        queue_head_time < cur_time)):
            self._rule_time_queue.insert(0, [new_rule_id])
            hub.kill(self._gthread_rule_dist)
            self._gthread_rule_dist = hub.spawn(
                self._distribute_rules_time)
            return

        # Now insert in order
        len_queue = len(self._rule_time_queue)
        new_rule_time_store = new_rule_time
        for i in range(len_queue):
            # Reset any changes made by timedelta
            new_rule_time = new_rule_time_store

            rule_i = self._access_control_list[
                self._rule_time_queue[i][0]]
            rule_i_time = dt.datetime.strptime(rule_i.time_start,
                                               "%H:%M")

            if new_rule_time == rule_i_time:
                self._rule_time_queue[i].append(new_rule_id)
                break

            if i == (len_queue - 1):
                # Reached the end of the queue
                self._rule_time_queue.append([new_rule_id])
                break

            if new_rule_time < cur_time and rule_i_time > new_rule_time:
                # The new rule has a 'smaller' time value than the current
                # time but its time for scheduling has already passed. This
                # means that the rule should be scheduled for tomorrow. To
                # correct the comparisons we'll add a day onto the datetime
                # value.
                new_rule_time = new_rule_time + dt.timedelta(1)

            if i == 0 and new_rule_time < rule_i_time:
                self._rule_time_queue.insert(0, [new_rule_id])
                break

            rule_i1 = self._access_control_list[
                self._rule_time_queue[i + 1][0]]
            rule_i1_time = dt.datetime.strptime(rule_i1.time_start,
                                                "%H:%M")

            if rule_i1_time < rule_i_time:
                # rule_i1_time may be smaller than rule_i_time but it
                # may be scheduled for tomorrow.
                rule_i1_time = rule_i1_time + dt.timedelta(1)

            if rule_i_time < new_rule_time and new_rule_time < rule_i1_time:
                self._rule_time_queue.insert(i + 1, [new_rule_id])
                break

    """
    Remove a rule_id from the queue of time scheduled ACL rules. If
    rule_id is at the head of the queue and it is the only rule that
    will be scheduled at its time, then the green thread managing the
    distribution of rules will need to be reset.

    @param new_rule_id - ID of the rule which needs to be scheduled.
    """

    def _remove_from_queue(self, rule_id):
        queue_head = True
        for time_period in self._rule_time_queue:
            for item in time_period:
                if item == rule_id:
                    time_period.remove(rule_id)
                    # Was this the only rule being scheduled
                    # at rule_id's time?
                    if len(time_period) < 1:
                        self._rule_time_queue.remove(time_period)
                        if queue_head:
                            hub.kill(self._gthread_rule_dist)
                            self._gthread_rule_dist = hub.spawn(
                                self._distribute_rules_time)
                    return
            queue_head = False

    # Methods handling ACL rule distribution

    """
    Proactively distribute a newly added rule to all connected switches.
    It is necessary to check the a switch is not given a rule for which
    it is not allowed to have. This is done by comparing policies.

    Called when a rule has been created.

    @param rule - the ACL rule to distributed among the switches.
    """

    def _distribute_single_rule(self, rule):
        for switch in self._connected_switches:
            switch_policies = self._connected_switches[switch]
            if rule.policy not in switch_policies:
                continue
            datapath = api.get_datapath(self, switch)
            priority = self.OFP_MAX_PRIORITY
            actions = []
            match = self._create_match(rule)
            if rule.time_duration == "N/A":
                self._add_flow(datapath, priority, match, actions,
                               table_id=self.TABLE_ID_ACL)
            else:
                self._add_flow(datapath, priority, match, actions,
                               time_limit=(int(rule.time_duration)),
                               table_id=self.TABLE_ID_ACL)

    """
    Proactively distribute hardcoded firewall rules to the switch
    specified using the datapath. Distribute the rules associated
    with the policy provided.

    Called when a switch is assigned a policy.

    @param datapath - an OF enabled switch to communicate with
    @param policy - the policy of the switch
    """

    def _distribute_rules_policy_set(self, datapath, policy):
        for rule_id in self._policy_to_rules[policy]:
            rule = self._access_control_list[rule_id]
            if rule.time_start == "N/A":
                priority = self.OFP_MAX_PRIORITY
                actions = []
                match = self._create_match(rule)
                self._add_flow(datapath, priority, match, actions,
                               table_id=self.TABLE_ID_ACL)

    """
    Distribute rules to switches when their time arises. An alarm must
    be scheduled to trigger this function to distrbute rules when
    needed.

    The next alarm is scheduled once all other necessary operations
    have been done.
    """

    def _distribute_rules_time(self):
        while True:
            # Check that the queue is not empty
            if len(self._rule_time_queue) < 1:
                break

            rule_id = self._rule_time_queue[0][0]
            rule = self._access_control_list[rule_id]
            time_start = rule.time_start
            # Normalise next_time
            next_scheduled = dt.datetime.strptime(time_start, "%H:%M")
            # The current time has to be normalised with the time in a rule
            # (i.e. the date of each datetime object is the same) before a
            # comparison can be made.
            current_time = dt.datetime.now().strftime("%H:%M:%S")
            normalised_current = dt.datetime.strptime(current_time,
                                                      "%H:%M:%S")
            # Compare the two times relative to the current time
            time_diff = (next_scheduled - normalised_current).seconds
            # Schedule the alarm to wait time_diff seconds
            print("[DEBUG] WAITING " + str(time_diff) + " seconds.")
            hub.sleep(time_diff)

            # Check that the queue is not empty again
            if len(self._rule_time_queue) < 1:
                break

            to_dist = self._rule_time_queue.pop(0)
            self._rule_time_queue.append(to_dist)

            rule = self._access_control_list[to_dist[0]]
            # Check that the current time matches the time of a rule at
            # the top of the queue, if not then reschedule the alarm.
            if rule.time_start != dt.datetime.now().strftime("%H:%M"):
                continue

            # Distribute the rules that need to be distributed now
            for rule_id in to_dist:
                self._distribute_single_rule(
                    self._access_control_list[rule_id])

            # Pause for moment to avoid flooding the switch with flow
            # mod messages. This happens because time_diff will be
            # evaluated again in the loop and it will be equal to 0
            # until a second passes.
            hub.sleep(self.TIME_PAUSE)

    # Methods handling OpenFlow flow table entries

    """
    Delete a flow table entry from a switch. OFPFC_DELETE_STRICT is used
    as you only want to remove exact matches of the rule.

    @param datapath - the switch to remove the flow table entry from.
    @param priority - priority of the rule to remove.
    @param match - the flow table entry to remove.
    """

    def _delete_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        command = ofproto.OFPFC_DELETE_STRICT
        mod = parser.OFPFlowMod(datapath=datapath, command=command,
                                priority=priority, match=match,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)

    """
    Reactively add a flow table entry to a switch's flow table.

    @param datapath - the switch to add the flow table entry to.
    @param time_limit - when the rule should expire.
    @param priority - priority of the rule to add.
    @param match - the flow table entry to add.
    @param actions - action for a switch to perform.
    @param buffer_id - identifier of buffer queue if traffic is being
                       buffered.
    """

    def _add_flow(self, datapath, priority, match, actions,
                  buffer_id=None, time_limit=0, table_id=1):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if (actions == None):
            # catch the moment where the flow tables are being linked up
            inst = [parser.OFPInstructionGotoTable(self.TABLE_ID_L2)]
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

    # Methods handling OpenFlow events

    """
    Event handler used when a switch connects to the controller.
    """

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry for the ACL flow table. No
        # buffer is used for this table-miss entry as matching flows
        # get passed onto the L2 switching flow table.
        match = parser.OFPMatch()
        actions = None  # no action required for forwarding to another table
        self._add_flow(datapath, 0, match, actions,
                       table_id=self.TABLE_ID_ACL)

        # Install table-miss flow entry for the L2 switching flow table.
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

        # The code below has been added by Jarrod N. Bakker
        # Take note of switches (via their datapaths)
        dp_id = ev.msg.datapath_id
        self._connected_switches[dp_id] = [self.POLICY_DEFAULT]

        print("[?] Switch " + str(dp_id) + " connected.")

        # Distribute the list of rules to the switch
        self._distribute_rules_policy_set(datapath, self.POLICY_DEFAULT)

    """
    Event handler used when a flow table entry is deleted.
    """

    @set_ev_cls(ofp_event.EventOFPFlowRemoved)
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        match = msg.match
        print("[?] Flow table entry removed.\n\t Flow match: "
              + str(match))

    """
    Event handler used when a switch receives a packet that it cannot
    match a flow table entry with.
    """

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
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

        self.logger.info("packet in %s %s %s %s", dpid, eth_src, eth_dst,
                         in_port)

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

            print
            "[?] New flow: " + str(pkt)
            priority = ofproto_v1_3.OFP_DEFAULT_PRIORITY

            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
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
