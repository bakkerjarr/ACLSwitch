# Module imports

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class PolicyManager:
    """Class that manages policy domains.
    """
    # TODO A number of these methods assume that the input is valid. Checks should be performed ideally.

    def __init__(self, logging):
        """Initialise the PolicyManager object.

        :param logging: ACLSWitch logging object.
        """
        self._logging = logging
        self._logging.info("Initialising PolicyManager...")
        self._connected_switches = {}  # switch_id_id:[policy]
        self._policy_to_rules = {}  # policy:[rule_id]

    def policy_create(self, policy):
        """Create a policy domain.

        :param policy: Name of the policy domain.
        :return: True if successful, False otherwise.
        """
        if self.policy_exists(policy):
            return False
        self._policy_to_rules[policy] = []
        return True

    def policy_exists(self, policy):
        """Check if a policy domain exists.

        :param policy: Name of a policy.
        :return: True if it exists already, False otherwise.
        """
        return policy in self._policy_to_rules

    def policy_get_rules(self, policy):
        """Return the rule IDs associated with a policy domain.

        :param policy: Policy domain from which to get rule IDs.
        :return: List of rule IDs.
        """
        return self._policy_to_rules[policy]

    def policy_get_switches(self, policy):
        """Return the switch IDs associated with a policy domain.

        :param policy: Policy domain from which to get switch IDs.
        :return: List of switch IDs.
        """
        switches = []
        for switch_id in self._connected_switches:
            if policy in self._connected_switches[switch_id]:
                switches.append(switch_id)
        return switches

    def policy_add_rule(self, policy, rule_id):
        """Add a rule to a policy domain.

        :param policy: Policy to assign rule to.
        :param rule_id: An ACL rule id.
        """
        self._policy_to_rules[policy].append(rule_id)

    def policy_remove_rule(self, policy, rule_id):
        """Remove a rule from a policy domain.

        :param policy: The policy domain to revoke a rule from.
        :param rule_id: An ACL rule.
        """
        self._policy_to_rules[policy].remove(rule_id)

    def switch_add(self, switch_id, policies):
        """Inform the policy manager that a switch has connected to
        the network and initialise it with a list of policies.

        :param switch_id: Switch identifier, typically the datapath ID.
        :param policies: List of policies to assign to the switch.
        """
        self._connected_switches[switch_id] = []
        for policy in policies:
            self.switch_assign_policy(switch_id, policy)

    def switch_assign_policy(self, switch_id, policy):
        """Assign a policy domain to a switch.

        :param switch_id: The switch to assign to.
        :param policy: The policy to assign.
        :return: True if the policy wasn't already assigned,
        False otherwise.
        """
        # send self._policy_to_rules[policy] to ACL
        if policy in self._connected_switches[switch_id]:
            return False
        self._connected_switches[switch_id] = policy
        return True

    def switch_revoke_policy(self, switch_id, policy):
        """Revoke a policy domain from a switch.

        :param switch_id: The switch to revoke from.
        :param policy: The policy to revoke.
        :return: True if successful, False otherwise.
        """
        pass
