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
# Author: Jarrod N. Bakker
# Part of an ENGR489 project at Victoria University of Wellington
# during 2015.
#
# This class manages the RESTful API calls to add rules etc.
#
# The RESTful interface code has been adapted from
# http://osrg.github.io/ryu-book/en/html/rest_api.html.
#

# Modules
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import route
from webob import Response
import json

# Global fields needed for REST linkage
acl_switch_instance_name = "acl_switch_app"
url = "/acl_switch"

class ACLSwitchREST(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(ACLSwitchREST, self).__init__(req, link, data, **config)
        self.acl_switch_inst = data[acl_switch_instance_name]
   
    # Methods for fetching information 
   
    """
    API call to return info on ACLSwitch. The number of policies, rules,
    switches and the current time of the machine that ACLSwitch is
    running on are returned. This should only be taken as an
    approximation of the current time therefore the time should only
    be accurate within minutes.

    """
    @route("acl_switch", url, methods=["GET"])
    def get_info(self, req, **kwargs):
        aclswitch_info = self.acl_switch_inst.get_info()
        body = json.dumps(aclswitch_info)
        return Response(content_type="application/json", body=body)

    """
    API call to show the switches and the policies associated with them.
    """
    @route("acl_switch", url+"/switches", methods=["GET"])
    def get_switch_list(self, req, **kwargs):
        body = json.dumps(self.acl_switch_inst.get_switches())
        return Response(content_type="application/json", body=body)

    """
    API call to return a list of the currently available policies.
    """
    @route("acl_switch", url+"/switch_policies", methods=["GET"])
    def get_policy_list(self, req, **kwargs):
        body = json.dumps({"Policies":self.acl_switch_inst.get_policy_list()})
        return Response(content_type="application/json", body=body)
    
    """
    API call to return the current contents of the ACL.
    """
    @route("acl_switch", url+"/acl_rules", methods=["GET"])
    def get_acl(self, req, **kwargs):
        acl = self.acl_switch_inst.get_acl()
        body = json.dumps(acl)
        return Response(content_type="application/json", body=body)

    """
    API call to return a list representing the queue of scheduled 
    """
    @route("acl_switch", url+"/acl_rules/time", methods=["GET"])
    def get_time_queue(self, req, **kwargs):
        body = json.dumps(self.acl_switch_inst.get_time_queue())
        return Response(content_type="application/json", body=body)

    # Methods dealing with policy management

    """
    API call to create a policy.
    """
    @route("acl_switch", url+"/switch_policies", methods=["POST"])
    def policy_create(self, req, **kwargs):
        try:
            create_req = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        try:
            policy = create_req["policy"]
        except:
            return Response(status=400, body="Invalid JSON passed.")
        result = self.acl_switch_inst.policy_create(policy)
        if result[0] == True:
            status = 200
        else:
            status = 400
        return Response(status=status, body=result[1])

    """
    API call to delete a policy from ACLSwitch.
    """
    @route("acl_switch", url+"/switch_policies", methods=["DELETE"])
    def policy_delete(self, req, **kwargs):
        try:
            delete_req = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        try:
            policy = delete_req["policy"]
        except:
            return Response(status=400, body="Invalid JSON passed.")
        result = self.acl_switch_inst.policy_delete(policy)
        if result[0] == True:
            status = 200
        else:
            status = 400
        return Response(status=status, body=result[1])

    """
    API call to assign a policy to a switch.
    """
    @route("acl_switch", url+"/switch_policies/assignment", methods=["PUT"])
    def policy_switch_assign(self, req, **kwargs):
        try:
            assignReq = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        try:
            switch_id = int(assignReq["switch_id"])
            new_policy = assignReq["new_policy"]
        except:
            return Response(status=400, body="Invalid JSON passed.")
        result = self.acl_switch_inst.policy_switch_assign(switch_id,
                                                         new_policy)
        if result[0] == True:
            status = 200
        else:
            status = 400
        return Response(status=status, body=result[1])

    """
    API call to remove a policy assignment from a switch.
    """
    @route("acl_switch", url+"/switch_policies/assignment", methods=["DELETE"])
    def policy_switch_remove(self, req, **kwargs):
        try:
            removeReq = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        try:
            switch_id = int(removeReq["switch_id"])
            old_policy = removeReq["old_policy"]
        except:
            return Response(status=400, body="Invalid JSON passed.")
        result = self.acl_switch_inst.policy_switch_remove(switch_id,
                                                         old_policy)
        if result[0] == True:
            status = 200
        else:
            status = 400
        return Response(status=status, body=result[1])

    # Methods dealing with rule management with the ACL

    """
    API call to add a rule to the ACL.
    """
    @route("acl_switch", url+"/acl_rules", methods=["POST"])
    def acl_rule_add(self, req, **kwargs):
        try:
            ruleReq = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        if not self.check_rule_json(ruleReq):
            return Response(status=400, body="Invalid JSON passed.")
        result = self.acl_switch_inst.acl_rule_add(ruleReq["ip_src"],
                                                   ruleReq["ip_dst"],
                                                   ruleReq["tp_proto"],
                                                   ruleReq["port_src"],
                                                   ruleReq["port_dst"],
                                                   ruleReq["policy"])
        if result[0] == False:
            return Response(status=400, body=result[1])
        return Response(status=200, body=result[1])

    """
    API call to add a rule which should be enforced for a period of time.
    """
    @route("acl_switch", url+"/acl_rules/time", methods=["POST"])
    def acl_rule_add_time(self, req, ** kwargs):
        try:
            ruleReq = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        if not self.check_rule_time_json(ruleReq):
            return Response(status=400, body="Invalid JSON passed.")
        result = self.acl_switch_inst.acl_rule_add(ruleReq["ip_src"],
                                                   ruleReq["ip_dst"],
                                                   ruleReq["tp_proto"],
                                                   ruleReq["port_src"],
                                                   ruleReq["port_dst"],
                                                   ruleReq["policy"],
                                                   ruleReq["time_start"],
                                                   ruleReq["time_duration"])
        if result[0] == False:
            return Response(status=400, body=result[1])
        return Response(status=200, body=result[1])


    """
    API call to add a rule for the whitelist or blacklist to the ACL.
    """

    @route("acl_switch", url+"/acl_rules/time", methods=["POST"])
    def acl_rule_add(self, req, **kwargs):
	try:
            ruleReq = json.loads(req.body)
	except:
	    return Response(status=400, body="Unable to parse JSON.")
        if not self.check_rule_time_json(ruleReq):
            return Response(status=400, body="Invalid JSON passed.")
	result = self.acl_switch_inst.acl_rule_add(ruleReq["ip_src"],
						   ruleReq["ip_dst"],
						   ruleReq["tp_proto"],
						   ruleReq["port_src"],
						   ruleReq["port_dst"],
						   ruleReq["policy"],
						   ruleReq["list"]

        if result[0] == False:
            return Response(status=400, body=result[1])
        return Response(status=200, body=result[1])





    """
    API call to remove a rule from the ACL.
    """
    @route("acl_switch", url+"/acl_rules", methods=["DELETE"])
    def acl_rule_remove(self, req, **kwargs):
        try:
            deleteReq = json.loads(req.body)
        except:
            return Response(status=400, body="Unable to parse JSON.")
        result = self.acl_switch_inst.acl_rule_delete(deleteReq["rule_id"])
        if result[0] == True:
            status = 200
        else:
            status = 400
        return Response(status=status, body=result[1])

    """
    Check that incoming JSON for an ACL has the required 6 fields:
    "ip_src", "ip_dst", "tp_proto", "port_src", "port_dst" and "policy".
    
    @param ruleJSON - input from the client to check.
    @return - True if ruleJSON is valid, False otherwise.
    """
    def check_rule_json(self, ruleJSON):
        if len(ruleJSON) != 6:
            return False
        if not "ip_src" in ruleJSON:
            return False
        if not "ip_dst" in ruleJSON:
            return False
        if not "tp_proto" in ruleJSON:
            return False
        if not "port_src" in ruleJSON:
            return False
        if not "port_dst" in ruleJSON:
            return False
        if not "policy" in ruleJSON:
            return False
        return True # everything is looking good!

    """
    Check that incoming JSON for an ACL has the required 8 fields:
    "ip_src", "ip_dst", "tp_proto", "port_src", "port_dst", "policy",
    "time_start" and "time_duration".
    
    @param ruleJSON - input from the client to check.
    @return - True if ruleJSON is valid, False otherwise.
    """
    def check_rule_time_json(self, ruleJSON):
        if len(ruleJSON) != 8:
            return False
        if not "ip_src" in ruleJSON:
            return False
        if not "ip_dst" in ruleJSON:
            return False
        if not "tp_proto" in ruleJSON:
            return False
        if not "port_src" in ruleJSON:
            return False
        if not "port_dst" in ruleJSON:
            return False
        if not "policy" in ruleJSON:
            return False
        if not "time_start" in ruleJSON:
            return False
        if not "time_duration" in ruleJSON:
            return False
        return True # everything is looking good!

    """
    Check that incoming JSON for a blacklist or whitelist ACL rule has the required 7 fields:
    "ip_src", "ip_dst", "tp_proto", "port_src", "port_dst", "policy" and "list"

    @param ruleJSON - input from the client to check.
    @return - True if ruleJSON is valid, False otherwise.
    """

    def check_rule_time_json(self, ruleJSON):
        if len(ruleJSON) != 7:
	    return False
        if not "ip_src" in ruleJSON:
	    return False
        if not "ip_dst" in ruleJSON:
	    return False
        if not "tp_proto" in ruleJSON:
	    return False
        if not "port_src" in ruleJSON:
	    return False
        if not "port_dst" in ruleJSON:
	    return False
        if not "policy" in ruleJSON:
	    return False
        if not "list" in ruleJSON:
	    return False
        return True # everything is looking good!
