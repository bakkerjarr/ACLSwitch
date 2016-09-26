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
from acl.acl_manager import ACLManager
from flow.flow_scheduler import FlowScheduler
from policy.policy_manager import PolicyManager

# Module imports
import logging

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ACLSwitchAPI:
    """API for modifying and viewing the state of ACLSwitch.
    """

    def __init__(self, logging_config, aclsw_version, flow_man):
        """Initialise the API class.

        :param logging_config: Logging configuration dict.
        :param aclsw_version: The current version of ACLSwitch.
        :param flow_man: FlowManager object.
        """
        self._logging = logging.getLogger(__name__)
        self._logging.setLevel(logging_config["min_lvl"])
        self._logging.propagate = logging_config["propagate"]
        self._logging.addHandler(logging_config["handler"])
        self._logging.info("Initialising API...")
        self._aclsw_version = aclsw_version
        self._flow_man = flow_man
        self._acl_man = ACLManager(logging_config)
        self._pol_man = PolicyManager(logging_config)
        self._flow_sch = FlowScheduler(logging_config, self, flow_man)

    def acl_create_rule(self, rule):
        """Create an ACL rule.

        :param rule: dict of the rule to create.
        :return: Result of the operation.
        """
        if not self._pol_man.policy_exists(rule["policy"]):
            return ReturnStatus.POLICY_NOT_EXISTS
        if not self._acl_man.acl_rule_syntax_check(rule):
            return ReturnStatus.RULE_SYNTAX_INVALID
        rule_id = self._acl_man.acl_add_rule(rule)
        if rule_id is None:
            return ReturnStatus.RULE_EXISTS
        self._pol_man.policy_add_rule(rule["policy"], rule_id)
        new_rule = self.acl_get_rule(rule_id)
        if new_rule.time_enforce == "N/A":
            switches = self.policy_get_connected_switches(rule["policy"])
            self._flow_man.flow_deploy_single_rule(new_rule, switches)
        else:
            self._flow_sch.sched_add_rule(rule_id, new_rule.time_enforce)
        return ReturnStatus.RULE_CREATED

    def acl_remove_rule(self, rule_id):
        """Remove an ACL rule.

        :param rule_id: ID of the rule to remove.
        :return: Result of the operation.
        """
        if not self._acl_man.acl_is_rule(rule_id):
            return ReturnStatus.RULE_NOT_EXISTS
        rule = self._acl_man.acl_remove_rule(rule_id)
        self._pol_man.policy_remove_rule(rule.policy, rule_id)
        switches = self.policy_get_switches(rule.policy)
        if rule.time_enforce == "N/A":
            switches = self.policy_get_connected_switches(rule.policy)
            self._flow_man.flow_remove_single_rule(rule, switches)
        else:
            self._flow_sch.sched_remove_rule(rule_id)
            self._flow_man.flow_remove_single_rule(rule, switches)
        return ReturnStatus.RULE_REMOVED

    def acl_get_rule(self, rule_id):
        """Return a rule given a rule ID.

        :param rule_id: ID of a rule.
        :return: Named tuple of a rule.
        """
        if not self._acl_man.acl_is_rule(rule_id):
            return -1
        return self._acl_man.acl_get_rule(rule_id)

    def policy_create(self, policy):
        """Create a policy domain.

        :param policy: Name of the policy domain.
        :return: Result of the operation.
        """
        if self._pol_man.policy_create(policy):
            return ReturnStatus.POLICY_CREATED
        else:
            return ReturnStatus.POLICY_EXISTS

    def policy_remove(self, policy):
        """Remove a policy domain.

        :param policy: Name of the policy domain.
        :return: Result of the operation.
        """
        if not self._pol_man.policy_exists(policy):
            return ReturnStatus.POLICY_NOT_EXISTS
        if not self._pol_man.policy_empty(policy):
            return ReturnStatus.POLICY_NOT_EMPTY
        self._pol_man.policy_remove(policy)
        return ReturnStatus.POLICY_REMOVED

    def policy_assign_switch(self, switch_id, policy, from_file=False):
        """Assign a policy to a switch assuming it has been registered.

        The switch does not have to exist if the assignment
        declaration is specified in a file. This does mean that the
        application could me DoSed by having many fake switches
        specified, however the benefit is that assignments can be
        specified in a file and loaded on application start-up. Such
        declarations result in switches being registered with the
        policy manager before they connect to controller. Care must
        then be taken to not send out flow table entries to the 'fake'
        switch. This functionality does not exist when the declaration
        is passed by the REST WSGI.

        :param switch_id: Switch identifier, typically the datapath ID.
        :param policy: Name of the policy to assign.
        :param from_file: False if the declaration came from the WSGI,
        True if it was specified in a file.
        """
        if not self._pol_man.switch_exists(switch_id):
            return ReturnStatus.SWITCH_NOT_EXISTS
        if not self._pol_man.policy_exists(policy):
            return ReturnStatus.POLICY_NOT_EXISTS
        if not self._pol_man.switch_assign_policy(switch_id, policy):
            return ReturnStatus.POLICY_ALREADY_ASSIGNED
        if not from_file and self._pol_man.switch_is_connected(
                switch_id):
            # Do not send out the rules if the switch has not connected.
            rule_ids = self._pol_man.policy_get_rules(policy)
            rules = []
            for r_id in rule_ids:
                rule = self.acl_get_rule(r_id)
                if rule.time_enforce == "N/A":
                    rules.append(rule)
            self._flow_man.flow_deploy_multiple_rules(switch_id, rules)
        return ReturnStatus.POLICY_ASSIGNED

    def policy_revoke_switch(self, switch_id, policy):
        """Revoke a policy assignment from a switch.

        :param switch_id: Switch identifier, typically the datapath ID.
        :param policy: Policy to revoke.
        """
        if not self._pol_man.switch_exists(switch_id):
            return ReturnStatus.SWITCH_NOT_EXISTS
        if not self._pol_man.policy_exists(policy):
            return ReturnStatus.POLICY_NOT_EXISTS
        if not self._pol_man.switch_revoke_policy(switch_id, policy):
            return ReturnStatus.POLICY_NOT_ASSIGNED
        if self._pol_man.switch_is_connected(switch_id):
            # Do not send out removal messages to switches that have
            # not connected.
            rule_ids = self._pol_man.policy_get_rules(policy)
            rules = []
            for r_id in rule_ids:
                rules.append(self.acl_get_rule(r_id))
            self._flow_man.flow_remove_multiple_rules(switch_id, rules)
        return ReturnStatus.POLICY_REVOKED

    def policy_get_switches(self, policy):
        """Return the IDs of switches assigned to a policy domain.

        :param policy: Policy domain name.
        :return: A list of switch IDs.
        """
        return self._pol_man.policy_get_switches(policy)

    def policy_get_connected_switches(self, policy):
        """Return the IDs os connected switches assigned to a policy
        domain.

        Note the connected distinction.

        :param policy: Policy domain name.
        :return: A list of switch IDs.
        """
        return self._pol_man.policy_get_connected_switches(policy)

    def switch_register(self, switch_id):
        """Register a switch with the policy manager.

        :param switch_id: Switch identifier, typically the datapath ID.
        :return: A return status.
        """
        if self._pol_man.switch_register(switch_id):
            return ReturnStatus.SWITCH_REGISTERED
        else:
            return ReturnStatus.SWITCH_EXISTS

    def switch_connect(self, switch_id):
        """Inform the policy manager that a switch has connected.

        :param switch_id: Switch identifier, typically the datapath ID.
        :return: A return status.
        """
        if self._pol_man.switch_connect(switch_id):
            rules = []
            for policy in self._pol_man.switch_get_policies(switch_id):
                rule_ids = self._pol_man.policy_get_rules(policy)
                for r_id in rule_ids:
                    rule = self.acl_get_rule(r_id)
                    if rule.time_enforce == "N/A":
                        rules.append(rule)
            self._flow_man.flow_deploy_multiple_rules(switch_id, rules)
            return ReturnStatus.SWITCH_CONNECTED
        else:
            return ReturnStatus.SWITCH_NOT_REGISTERED

    def get_aclswitch_info(self):
        """Fetch and return a dict containing a summary of the state
        of ACLSwitch.

        :return: A dict containing some summary information.
        """
        return {"num_rules": self._acl_man.get_num_rules(),
                "num_policies": self._pol_man.get_num_policies(),
                "num_switches": self._pol_man.get_num_switches(),
                "version": self._aclsw_version}

    def get_all_policies(self):
        """Fetch and return a dict of policies and the rules that are
        associated with them.

        :return: A dict of policies to a list of rule IDs.
        """
        return {"policies": self._pol_man.get_all_policies()}

    def get_all_rules(self):
        """Fetch and return a dict of ACL rule IDs to their respective
        ACL rules.

        :return: A dict containing all ACL rules.
        """
        return {"acl": self._acl_man.get_all_rules()}

    def get_all_switches(self):
        """Fetch and return a dict of the IDs of connected switches
        and the policies assigned to them.

        :return: A dict of switch IDs to a list of policies.
        """
        return {"switches": self._pol_man.get_all_switches()}

    def get_time_queue(self):
        """Fetch and return the time enforced ACL rule queue.

        :return: The time queue as a list of lists.
        """
        return {"time_queue": self._flow_sch.get_time_queue()}


class ReturnStatus:
    """Enums for function return statuses.
    """
    POLICY_EXISTS = 10
    POLICY_NOT_EXISTS = 11
    POLICY_CREATED = 12
    POLICY_REMOVED = 13
    POLICY_NOT_EMPTY = 14
    POLICY_ASSIGNED = 15
    POLICY_NOT_ASSIGNED = 16
    POLICY_ALREADY_ASSIGNED = 17
    POLICY_REVOKED = 18
    RULE_EXISTS = 20
    RULE_NOT_EXISTS = 21
    RULE_CREATED = 22
    RULE_REMOVED = 23
    RULE_SYNTAX_INVALID = 24
    SWITCH_EXISTS = 30
    SWITCH_NOT_EXISTS = 31
    SWITCH_REGISTERED = 32
    SWITCH_NOT_REGISTERED = 33
    SWITCH_CONNECTED = 34
