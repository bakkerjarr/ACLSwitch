# ACLSwitch modules
from acl.acl_manager import ACLManager
from policy.policy_manager import PolicyManager

# Module imports

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ACLSwitchAPI:
    """API for modifying and viewing the state of ACLSwitch.
    """

    def __init__(self, logging, flow_man):
        """Initialise the API class.

        :param logging: ACLSWitch logging object.
        :param flow_man: FlowManager object.
        """
        self._logging = logging
        self._logging.info("Initialising API...")
        self._flow_man = flow_man
        self._acl_man = ACLManager(self._logging)
        self._pol_man = PolicyManager(self._logging)

    def acl_create_rule(self, rule):
        """Endpoint for creating an ACL rule.

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
        self._pol_man.rule_assign_policy(rule["policy"], rule_id)
        switches = self._pol_man.policy_get_switches(rule["policy"])
        self._flow_man.flow_deploy_single_rule(rule, switches)
        return ReturnStatus.RULE_CREATED

    def acl_remove_rule(self, rule_id):
        pass

    def acl_get_rule(self, rule_id):
        """Return a rule given a rule ID.

        :param rule_id: ID of a rule.
        :return: Named tuple of a rule.
        """
        # TODO This method assumes that the rule_id is valid.
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

    def policy_remove(self):
        pass

    def policy_assign(self):
        pass

    def policy_revoke(self):
        pass

    def policy_add_switch(self, switch_id, policies):
        """Inform the policy manager that a switch has connected to
        the network.

        :param switch_id: Switch identifier, typically the datapath ID.
        :param policies: List of policies to assign to the switch.
        """
        self._pol_man.switch_add(switch_id, policies)
        rule_ids = []
        for policy in policies:
            rule_ids = rule_ids + self._pol_man.policy_get_rules(policy)
        print(rule_ids)
        rules = []
        for r_id in rule_ids:
            rules.append(self.acl_get_rule(r_id))
        self._flow_man.flow_deploy_multiple_rules(switch_id, rules)

class ReturnStatus:
    """Enums for function return statuses.
    """
    POLICY_EXISTS = 10
    POLICY_NOT_EXISTS = 11
    POLICY_CREATED = 12
    POLICY_REMOVED = 13
    RULE_EXISTS = 20
    RULE_NOT_EXISTS = 21
    RULE_CREATED = 22
    RULE_REMOVED = 23
    RULE_SYNTAX_INVALID = 24

