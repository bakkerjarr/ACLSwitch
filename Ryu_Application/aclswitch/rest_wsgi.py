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

# ACLSwitch modules
from aclswitch_api import ReturnStatus

# Module imports
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import route
from webob import Response
import json
import time

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ACLSwitchREST(ControllerBase):

    # Fields for kwargs
    _INSTANCE_NAME_CONTR = "ryu_controller_abstraction"
    _INSTANCE_NAME_ASW_API = "asw_api"
    # Outgoing message templates
    _MSG_CRITICAL = {"critical": ""}
    _MSG_ERROR = {"error": ""}
    _MSG_HB = {"heartbeat": ""}
    _MSG_INFO = {"info": ""}
    _MSG_WARNING = {"warning": ""}
    # URLs
    _URL = "/aclswitch"
    _URL_HEARTBEAT = _URL + "/heartbeat"
    _URL_ACL = _URL + "/acl"
    _URL_ACL_TIME = _URL_ACL + "/time"
    _URL_POLICY = _URL + "/policy"
    _URL_POLICY_ASSIGN = _URL_POLICY + "/assignment"
    _URL_SWITCH = _URL + "/switch"

    def __init__(self, req, link, data, **config):
        super(ACLSwitchREST, self).__init__(req, link, data, **config)
        self._acl_switch_inst = data[self._INSTANCE_NAME_CONTR]
        self._api = data[self._INSTANCE_NAME_ASW_API]

    # TODO need to handle cases where the client sends JSON that we don't recognise.

    ######
    ### General ACLSwitch endpoints
    ######

    @route("aclswitch", _URL, methods=["GET"])
    def get_info(self, req, **kwargs):
        """Endpoint for the base URL.

        :return: A response with a simple welcome message.
        """
        aclswitch_info = {"msg": "Welcome to the ACLSwitch REST WSGI."}
        aclswitch_info.update(self._api.get_aclswitch_info())
        body = json.dumps(aclswitch_info)
        return Response(content_type="application/json", status=200,
                        body=body)

    @route("aclswitch", _URL_HEARTBEAT, methods=["GET"])
    def heartbeat(self, req, **kwargs):
        """Endpoint for WSGI heartbeat.

        :return: A response with a simple message indicating the
        heartbeat.
        """
        heartbeat = self._MSG_HB.copy()
        heartbeat["heartbeat"] = time.ctime()
        return Response(content_type="application/json",
                        body=json.dumps(heartbeat))

    ######
    ### ACL endpoints
    ######

    @route("aclswitch", _URL_ACL, methods=["GET"])
    def get_acls(self, req, **kwargs):
        """Endpoint for fetching a list of all the ACL rules.

        :return: A response containing a JSON formatted list of all
        ACL rules.
        """
        body = self._MSG_INFO.copy()
        body["info"] = self._api.get_all_rules()
        return Response(content_type="application/json", status=200,
                        body=json.dumps(body))

    @route("aclswitch", _URL_ACL_TIME, methods=["GET"])
    def get_acls_time(self, req, **kwargs):
        """Endpoint for fetching the rules in the time queue.

        :return: A response containing a JSON formatted list of all
        time enforced ACL rules.
        """
        body = self._MSG_INFO.copy()
        body["info"] = self._api.get_time_queue()
        return Response(content_type="application/json", status=200,
                        body=json.dumps(body))

    @route("aclswitch", _URL_ACL, methods=["POST"])
    def post_acl(self, req, **kwargs):
        """Endpoint for creating an ACL rule.

        :return: A response containing the result of the operation.
        """
        try:
            rule_req = json.loads(req.body)
        except ValueError:
            error = self._MSG_ERROR.copy()
            error["error"] = "Unable to parse JSON."
            return Response(status=400, body=json.dumps(error))
        return_status = self._api.acl_create_rule(rule_req["rule"])
        return self._api_response(return_status)

    @route("aclswitch", _URL_ACL, methods=["DELETE"])
    def delete_acl(self, req, **kwargs):
        """Endpoint for removing an ACL rule.

        :return: A response containing the result of the operation.
        """
        try:
            rule_req = json.loads(req.body)
        except ValueError:
            return Response(status=400, body="Unable to parse JSON.")
        return_status = self._api.acl_remove_rule(rule_req["rule_id"])
        return self._api_response(return_status)

    ######
    ### Policy endpoints
    ######

    @route("aclswitch", _URL_POLICY, methods=["GET"])
    def get_policies(self, req, **kwargs):
        """Endpoint for fetching a list of all the policies.

        :return: A response containing a JSON formatted list of all
        policies and the rule IDs associated with each policy.
        """
        body = self._MSG_INFO.copy()
        body["info"] = self._api.get_all_policies()
        return Response(content_type="application/json", status=200,
                        body=json.dumps(body))

    @route("aclswitch", _URL_POLICY, methods=["POST"])
    def post_policy(self, req, **kwargs):
        """Endpoint for creating a policy.

        :return: A response containing the result of the operation.
        """
        try:
            policy_req = json.loads(req.body)
        except ValueError:
            return Response(status=400, body="Unable to parse JSON.")
        return_status = self._api.policy_create(policy_req["policy"])
        return self._api_response(return_status)

    @route("aclswitch", _URL_POLICY, methods=["DELETE"])
    def delete_policy(self, req, **kwargs):
        """Endpoint for removing a policy.

        :return: A response containing the result of the operation.
        """
        try:
            policy_req = json.loads(req.body)
        except ValueError:
            return Response(status=400, body="Unable to parse JSON.")
        return_status = self._api.policy_remove(policy_req["policy"])
        return self._api_response(return_status)

    @route("aclswitch", _URL_POLICY_ASSIGN, methods=["PUT"])
    def put_policy_assign(self, req, **kwargs):
        """Endpoint for assigning a policy to a switch.

        :return: A response containing the result of the operation.
        """
        try:
            policy_assign_req = json.loads(req.body)
        except ValueError:
            return Response(status=400, body="Unable to parse JSON.")
        return_status = self._api.policy_assign_switch(
            policy_assign_req["switch_id"], policy_assign_req["policy"])
        return self._api_response(return_status)

    @route("aclswitch", _URL_POLICY_ASSIGN, methods=["DELETE"])
    def delete_policy_revoke(self, req, **kwargs):
        """Endpoint for revoking a policy from a switch.

        :return: A response containing the result of the operation.
        """
        try:
            policy_revoke_req = json.loads(req.body)
        except ValueError:
            return Response(status=400, body="Unable to parse JSON.")
        return_status = self._api.policy_revoke_switch(
            policy_revoke_req["switch_id"], policy_revoke_req["policy"])
        return self._api_response(return_status)

    ######
    ### Switch endpoints
    ######

    @route("aclswitch", _URL_SWITCH, methods=["GET"])
    def get_switches(self, req, **kwargs):
        """Endpoint for fetching a list of all currently connected
        switches.

        :return: A response containing a JSON formatted list of all
        currently connected switches and the policy domains assigned
        to each switch.
        """
        body = self._MSG_INFO.copy()
        body["info"] = self._api.get_all_switches()
        return Response(content_type="application/json", status=200,
                        body=json.dumps(body))

    ######
    ### Helper functions
    ######

    def _api_response(self, return_status):
        """Put together a Response object for a given ReturnStatus code.

        :param return_status: The ReturnStatus integer code.
        :return: The Response object.
        """
        if return_status == ReturnStatus.POLICY_EXISTS:
            status = 400
            body = self._MSG_WARNING.copy()
            body["warning"] = "The policy domain already exists."
        elif return_status == ReturnStatus.POLICY_NOT_EXISTS:
            status = 400
            body = self._MSG_WARNING.copy()
            body["warning"] = "The policy domain does not exist."
        elif return_status == ReturnStatus.POLICY_CREATED:
            status = 200
            body = self._MSG_INFO.copy()
            body["info"] = "Policy domain created."
        elif return_status == ReturnStatus.POLICY_REMOVED:
            status = 200
            body = self._MSG_INFO.copy()
            body["info"] = "Policy domain removed."
        elif return_status == ReturnStatus.POLICY_NOT_EMPTY:
            status = 400
            body = self._MSG_WARNING.copy()
            body["warning"] = "The policy domain cannot be removed as " \
                              "it has rules associated with it."
        elif return_status == ReturnStatus.POLICY_ASSIGNED:
            status = 200
            body = self._MSG_INFO.copy()
            body["info"] = "Policy domain assigned to the switch."
        elif return_status == ReturnStatus.POLICY_NOT_ASSIGNED:
            status = 400
            body = self._MSG_WARNING.copy()
            body["warning"] = "The policy domain is not assigned to " \
                              "the switch."
        elif return_status == ReturnStatus.POLICY_ALREADY_ASSIGNED:
            status = 400
            body = self._MSG_WARNING.copy()
            body["warning"] = "The policy domain is already assigned " \
                              "to the switch."
        elif return_status == ReturnStatus.POLICY_REVOKED:
            status = 200
            body = self._MSG_INFO.copy()
            body["info"] = "Policy domain revoked from the switch."
        elif return_status == ReturnStatus.RULE_EXISTS:
            status = 400
            body = self._MSG_WARNING.copy()
            body["warning"] = "The ACL rule already exists."
        elif return_status == ReturnStatus.RULE_NOT_EXISTS:
            status = 400
            body = self._MSG_WARNING.copy()
            body["warning"] = "The ACL rule does not exists."
        elif return_status == ReturnStatus.RULE_CREATED:
            status = 200
            body = self._MSG_INFO.copy()
            body["info"] = "ACL rule created."
        elif return_status == ReturnStatus.RULE_REMOVED:
            status = 200
            body = self._MSG_INFO.copy()
            body["info"] = "ACL rule removed."
        elif return_status == ReturnStatus.RULE_SYNTAX_INVALID:
            status = 400
            body = self._MSG_ERROR.copy()
            body["error"] = "Incorrect ACL rule syntax."
        elif return_status == ReturnStatus.SWITCH_NOT_EXISTS:
            status = 400
            body = self._MSG_WARNING.copy()
            body["warning"] = "The switch does not exist."
        else:
            status = 500
            body = self._MSG_CRITICAL.copy()
            body["critical"] = "Unrecognised ReturnStatus passed. " \
                               "Please contact an ACLSwitch developer " \
                               "immediately."
        return Response(content_type="application/json", status=status,
                        body=json.dumps(body))
