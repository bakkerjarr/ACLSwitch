# ACLSwitch modules
from aclswitch_api import ReturnStatus

# Module imports
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import route
from webob import Response
import json

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ACLSwitchREST(ControllerBase):

    # Fields for kwargs
    _INSTANCE_NAME_CONTR = "ryu_controller_abstraction"
    _INSTANCE_NAME_ASW_API = "asw_api"
    # URLs
    _URL = "/aclswitch"
    _URL_HEARTBEAT = _URL + "/heartbeat"
    _URL_ACL = _URL + "/acl"
    _URL_POLICY = _URL + "/policy"
    _URL_POLICY_ASSIGN = _URL_POLICY + "/assignment"
    _URL_SWITCH = _URL + "/switch"

    def __init__(self, req, link, data, **config):
        super(ACLSwitchREST, self).__init__(req, link, data, **config)
        self._acl_switch_inst = data[self._INSTANCE_NAME_CONTR]
        self._api = data[self._INSTANCE_NAME_ASW_API]

    ######
    ### General ACLSwitch endpoints
    ######

    @route("aclswitch", _URL, methods=["GET"])
    def get_info(self, req, **kwargs):
        """Endpoint for the base URL.

        :return: A response with a simple welcome message.
        """
        aclswitch_info = {"msg": "Welcome to the ACLSwitch REST WSGI."}
        body = json.dumps(aclswitch_info)
        return Response(content_type="application/json", body=body)

    @route("aclswitch", _URL_HEARTBEAT, methods=["GET"])
    def heartbeat(self, req, **kwargs):
        """Endpoint for WSGI heartbeat.

        :return: A response with a simple message indicating the
        heartbeat.
        """
        body = json.dumps({"msg": "heartbeat"})
        return Response(content_type="application/json", body=body)

    ######
    ### ACL endpoints
    ######
    @route("aclswitch", _URL_ACL, methods=["GET"])
    def get_acls(self, req, **kwargs):
        """Endpoint for fetching a list of all the ACL rules.

        :return: A response containing a JSON formatted list of all
        ACL rules.
        """
        # TODO Complete endpoint
        body = json.dumps("get_acls endpoint set.")
        return Response(content_type="application/json", body=body)

    @route("aclswitch", _URL_ACL, methods=["POST"])
    def post_acl(self, req, **kwargs):
        """Endpoint for creating an ACL rule.

        :return: A response containing the result of the operation.
        """
        try:
            rule_req = json.loads(req.body)
        except ValueError:
            return Response(status=400, body="Unable to parse JSON.")
        result = self._api.acl_create_rule(rule_req["rule"])
        # TODO send success response

    @route("aclswitch", _URL_ACL, methods=["DELETE"])
    def delete_acl(self, req, **kwargs):
        """Endpoint for removing an ACL rule.

        :return: A response containing the result of the operation.
        """
        try:
            rule_req = json.loads(req.body)
        except ValueError:
            return Response(status=400, body="Unable to parse JSON.")
        rseult = self._api.acl_remove_rule(rule_req["rule_id"])
        # TODO send success response

    ######
    ### Policy endpoints
    ######
    @route("aclswitch", _URL_POLICY, methods=["GET"])
    def get_policies(self, req, **kwargs):
        """Endpoint for fetching a list of all the policies.

        :return: A response containing a JSON formatted list of all
        policies and the rule IDs associated with each policy.
        """
        # TODO Complete endpoint
        body = json.dumps("get_policies endpoint set.")
        return Response(content_type="application/json", body=body)

    @route("aclswitch", _URL_POLICY, methods=["POST"])
    def post_policy(self, req, **kwargs):
        """Endpoint for creating a policy.

        :return: A response containing the result of the operation.
        """
        try:
            policy_req = json.loads(req.body)
        except ValueError:
            return Response(status=400, body="Unable to parse JSON.")
        result = self._api.policy_create(policy_req["policy"])
        print(result)
        # TODO send success response

    @route("aclswitch", _URL_POLICY, methods=["DELETE"])
    def delete_policy(self, req, **kwargs):
        """Endpoint for removing a policy.

        :return: A response containing the result of the operation.
        """
        try:
            policy_req = json.loads(req.body)
        except ValueError:
            return Response(status=400, body="Unable to parse JSON.")
        result = self._api.policy_remove(policy_req["policy"])
        print(result)
        # TODO send success response

    @route("aclswitch", _URL_POLICY_ASSIGN, methods=["PUT"])
    def put_policy_assign(self, req, **kwargs):
        """Endpoint for assigning a policy to a switch.

        :return: A response containing the result of the operation.
        """
        try:
            policy_assign_req = json.loads(req.body)
        except ValueError:
            return Response(status=400, body="Unable to parse JSON.")
        result = self._api.policy_assign_switch(policy_assign_req[
                                                    "switch_id"],
                                                policy_assign_req[
                                                    "policy"])
        print(result)
        # TODO send success response

    @route("aclswitch", _URL_POLICY_ASSIGN, methods=["DELETE"])
    def delete_policy_revoke(self, req, **kwargs):
        """Endpoint for revoking a policy from a switch.

        :return: A response containing the result of the operation.
        """
        try:
            policy_revoke_req = json.loads(req.body)
        except ValueError:
            return Response(status=400, body="Unable to parse JSON.")
        result = self._api.policy_revoke_switch(policy_revoke_req[
                                                    "switch_id"],
                                                policy_revoke_req[
                                                    "policy"])
        # TODO send success response

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
        # TODO Complete endpoint
        body = json.dumps("get_switches endpoint set.")
        return Response(content_type="application/json", body=body)
