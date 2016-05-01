# ACLSwitch modules
from acl.acl_manager import ACLManager
from policy.policy_manager import PolicyManager

# Module imports
import logging

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ACLSwitchAPI:
    """API for modifying and viewing the state of ACLSwitch.
    """

    def __init__(self, logging_config, flow_man):
        """Initialise the API class.

        :param logging_config: Logging configuration dict.
        :param flow_man: FlowManager object.
        """
        self._logging = logging.getLogger(__name__)
        self._logging.setLevel(logging_config["min_lvl"])
        self._logging.propagate = logging_config["propagate"]
        self._logging.addHandler(logging_config["handler"])
        self._logging.info("Initialising API...")
        self._flow_man = flow_man
        self._acl_man = ACLManager(logging_config)
        self._pol_man = PolicyManager(logging_config)

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
        switches = self._pol_man.policy_get_switches(rule["policy"])
        self._flow_man.flow_deploy_single_rule(self.acl_get_rule(
            rule_id), switches)
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
        switches = self._pol_man.policy_get_switches(rule.policy)
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

    def policy_assign_switch(self, switch_id, policy):
        """Assign a policy to a switch.

        :param switch_id: Switch identifier, typically the datapath ID.
        :param policy: Name of the policy to assign.
        """
        if not self._pol_man.switch_exists(switch_id):
            return ReturnStatus.SWITCH_NOT_EXISTS
        if not self._pol_man.policy_exists(policy):
            return ReturnStatus.POLICY_NOT_EXISTS
        if not self._pol_man.switch_assign_policy(switch_id, policy):
            return ReturnStatus.POLICY_ASSIGNED
        rule_ids = self._pol_man.policy_get_rules(policy)
        rules = []
        for r_id in rule_ids:
            rules.append(self.acl_get_rule(r_id))
        self._flow_man.flow_deploy_multiple_rules(switch_id, rules)

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
        rule_ids = self._pol_man.policy_get_rules(policy)
        rules = []
        for r_id in rule_ids:
            rules.append(self.acl_get_rule(r_id))
        self._flow_man.flow_remove_multiple_rules(switch_id, rules)

    def switch_connect(self, switch_id):
        """A switch has connected to the network, inform the policy
        manager.

        :param switch_id:
        """
        if self._pol_man.switch_connect(switch_id):
            return ReturnStatus.SWITCH_CREATED
        else:
            return ReturnStatus.SWITCH_EXISTS

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
    RULE_EXISTS = 20
    RULE_NOT_EXISTS = 21
    RULE_CREATED = 22
    RULE_REMOVED = 23
    RULE_SYNTAX_INVALID = 24
    SWITCH_EXISTS = 30
    SWITCH_NOT_EXISTS = 31
    SWITCH_CREATED = 32
