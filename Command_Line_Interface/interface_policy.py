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
# This file contains the logic for handling the assignment or removal of
# policy to and from switches. This allows for much richer network security
# policy enforcement.
#
# Author: Jarrod N. Bakker
#

# Libraries
import json
import requests

class ACLInterfacePolicy:

    # Constants
    PROMPT_POLICY = "ACL Switch (policy) > "
    PROMPT_POLICY_ASSIGN = "ACL Switch (policy -> assign) > "
    PROMPT_POLICY_CREATE = "ACL Switch (policy -> create) > "
    PROMPT_POLICY_DELETE = "ACL Switch (policy -> delete) > "
    PROMPT_POLICY_REMOVE = "ACL Switch (policy -> remove) > "
    TEXT_ERROR_SYNTAX = "ERROR: Incorrect syntax, could not process given command."
    TEXT_ERROR_CONNECTION = "ERROR: Unable to establish a connection with ACLSwitch."
    TEXT_HELP_POLICY = "\tcreate, delete (policy), assign OR remove (assignment)"
    TEXT_HELP_POLICY_ASSIGN = "\tPolicy to assign: switch_id policy"
    TEXT_HELP_POLICY_CREATE = "\tPolicy to create: policy"
    TEXT_HELP_POLICY_DELETE = "\tPolicy to delete: policy"
    TEXT_HELP_POLICY_REMOVE = "\tPolicy to remove: switch_id policy"
    URL_ACLSWITCH_POLICY = "http://127.0.0.1:8080/acl_switch/switch_policies" # using loopback
    
    """
    Assign interface. The user can assign or remove a policy from a switch.
    This allows the switch to block different ranges of traffic compared
    to other switches within the network.
    """
    def __init__(self):
        print self.TEXT_HELP_POLICY
        buf_in = raw_input(self.PROMPT_POLICY)
        if buf_in == "create":
            self.policy_create()
        elif buf_in == "delete":
            self.policy_delete()
        elif buf_in == "assign":
            self.policy_switch_assign()
        elif buf_in == "remove":
            self.policy_switch_remove()
        else:
            print(self.TEXT_ERROR_SYNTAX + "\n" + self.TEXT_HELP_POLICY) # syntax error
    
    """
    Create a policy.
    """
    def policy_create(self):
        print self.TEXT_HELP_POLICY_CREATE
        policy = raw_input(self.PROMPT_POLICY_CREATE)
        if " " in policy:
            print("Policy name cannot contain space character.")
            return
        create_req = json.dumps({"policy":policy})
        try:
            resp = requests.post(self.URL_ACLSWITCH_POLICY, data=create_req,
                                 headers={"Content-type":"application/json"})
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error modifying resource, HTTP " + str(resp.status_code))
        print resp.text

    """
    Delete a policy.
    """
    def policy_delete(self):
        print self.TEXT_HELP_POLICY_DELETE
        policy = raw_input(self.PROMPT_POLICY_DELETE)
        if " " in policy:
            print("Policy name cannot contain space character.")
            return
        delete_req = json.dumps({"policy":policy})
        try:
            resp = requests.delete(self.URL_ACLSWITCH_POLICY, data=delete_req,
                                   headers={"Content-type":"application/json"})
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error modifying resource, HTTP " + str(resp.status_code))
        print resp.text

    """
    Assign a policy to a switch.
    """
    def policy_switch_assign(self):
        print self.TEXT_HELP_POLICY_ASSIGN
        buf_in = raw_input(self.PROMPT_POLICY_ASSIGN)
        new_assign = buf_in.split(" ")
        if len(new_assign) != 2:
            print("Expect 2 arguments, " + str(len(new_assign)) + " given.")
            return
        try:
            int(new_assign[0])
            if int(new_assign[0]) < 1:
                print "Switch id should be a positive integer greater than 1."
                return
        except:
            print "Switch id should be a positive integer greater than 1."
            return
        assign_req = json.dumps({"switch_id":new_assign[0],
                                 "new_policy":new_assign[1]})
        try:
            resp = requests.put(self.URL_ACLSWITCH_POLICY+"/assignment",
                                data=assign_req,
                                headers={"Content-type":"application/json"})
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error modifying resource, HTTP " + str(resp.status_code))
        print resp.text

    """
    Remove an assigned policy from a switch.
    """
    def policy_switch_remove(self):
        print self.TEXT_HELP_POLICY_REMOVE
        buf_in = raw_input(self.PROMPT_POLICY_REMOVE)
        removal = buf_in.split(" ")
        if len(removal) != 2:
            print("Expect 2 arguments, " + str(len(removal)) + " given.")
            return
        try:
            int(removal[0])
            if int(removal[0]) < 1:
                print "Switch id should be a positive integer greater than 1."
                return
        except:
            print "Switch id should be a positive integer greater than 1."
            return
        remove_req = json.dumps({"switch_id":removal[0],
                                 "old_policy":removal[1]})
        try:
            resp = requests.delete(self.URL_ACLSWITCH_POLICY+"/assignment",
                                   data=remove_req,
                                   headers = {"Content-type":"application/json"})
        except:
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error deleting resource, HTTP " + str(resp.status_code))
        print resp.text

