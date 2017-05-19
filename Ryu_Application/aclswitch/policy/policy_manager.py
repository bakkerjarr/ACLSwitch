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
from aclswitch.policy.switch import Switch

# Module imports
import logging

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class PolicyManager:
    """Class that manages policy domains.
    """

    def __init__(self, logging_config):
        """Initialise the PolicyManager object.

        :param logging_config: Logging configuration dict.
        """
        self._logging = logging.getLogger(__name__)
        self._logging.setLevel(logging_config["min_lvl"])
        self._logging.propagate = logging_config["propagate"]
        self._logging.addHandler(logging_config["handler"])
        self._logging.info("Initialising PolicyManager...")
        self._switches = {}  # switch_id_id:switch
        self._policy_to_rules = {}  # policy:[rule_id]

    def policy_create(self, policy):
        """Create a policy domain.

        :param policy: Name of the policy domain.
        :return: True if successful, False otherwise.
        """
        if self.policy_exists(policy):
            self._logging.warning("Cannot create policy %s as it "
                                  "already exists.", policy)
            return False
        self._policy_to_rules[policy] = []
        self._logging.info("Created policy: %s", policy)
        return True

    def policy_remove(self, policy):
        """Remove a policy domain.

        Assumes the policy has no rules with it.

        :param policy: Name of the policy domain.
        :return: True if successful, False otherwise.
        """
        if not self.policy_exists(policy):
            self._logging.warning("Cannot remove policy %s as it does "
                                  "not exist.", policy)
            return False
        # We must revoke the policy from switches that have it assigned
        for switch_id in self._switches:
            if self._switches[switch_id].has_policy(policy):
                self.switch_revoke_policy(switch_id, policy)
        del self._policy_to_rules[policy]
        self._logging.info("Removed policy: %s", policy)
        return True

    def policy_exists(self, policy):
        """Check if a policy domain exists.

        :param policy: Name of a policy.
        :return: True if it exists already, False otherwise.
        """
        if policy in self._policy_to_rules:
            self._logging.debug("Policy %s exists.", policy)
            return True
        self._logging.debug("Policy %s does not exists.", policy)
        return False

    def policy_empty(self, policy):
        """Check if a policy has no rules associated with it.

        :param policy: Policy to check.
        :return: True if no rules are assigned, False otherwise.
        """
        if len(self._policy_to_rules[policy]) > 0:
            self._logging.warning("Policy %s has rules associated "
                                  "with it.", policy)
            return False
        self._logging.debug("Policy %s has no rules associated with "
                            "it.", policy)
        return True

    def policy_get_rules(self, policy):
        """Return the rule IDs associated with a policy domain.

        :param policy: Policy domain from which to get rule IDs.
        :return: List of rule IDs.
        """
        return self._policy_to_rules[policy]

    def policy_get_switches(self, policy):
        """Return the IDs of switches assigned to a policy domain.

        :param policy: Policy domain from which to get switch IDs.
        :return: List of switch IDs.
        """
        switches = []
        for switch_id in self._switches:
            if self._switches[switch_id].has_policy(policy):
                switches.append(switch_id)
        return switches

    def policy_get_connected_switches(self, policy):
        """Return the IDs os connected switches assigned to a policy
        domain.

        Note the connected distinction.

        :param policy: Policy domain from which to get switch IDs.
        :return: List of switch IDs.
        """
        switches = []
        for switch_id in self._switches:
            switch = self._switches[switch_id]
            if switch.has_policy(policy) and switch.is_connected():
                switches.append(switch_id)
        return switches

    def policy_add_rule(self, policy, rule_id):
        """Add a rule to a policy domain.

        :param policy: Policy to assign rule to.
        :param rule_id: An ACL rule id.
        """
        self._policy_to_rules[policy].append(rule_id)
        self._logging.debug("Rule %s added to policy %s.", rule_id,
                            policy)

    def policy_remove_rule(self, policy, rule_id):
        """Remove a rule from a policy domain.

        :param policy: The policy domain to revoke a rule from.
        :param rule_id: An ACL rule.
        """
        self._policy_to_rules[policy].remove(rule_id)
        self._logging.debug("Rule %s removed from policy %s.",
                            rule_id, policy)

    def switch_register(self, switch_id):
        """Register a switch with the policy manager.

        Note that a switch may be registered but not connected.

        :param switch_id: Switch identifier, typically the datapath ID.
        :return: True if the switch has not registered before,
        False otherwise.
        """
        if switch_id in self._switches:
            self._logging.info("Switch %s already registered.",
                               switch_id)
            return False
        self._switches[switch_id] = Switch(switch_id)
        self._logging.info("Switch %s registered.", switch_id)
        return True

    def switch_connect(self, switch_id):
        """Inform the policy manager that a switch has connected to
        the network.

        :param switch_id: Switch identifier, typically the datapath ID.
        :return: True if the switch has not connected before,
        False otherwise.
        """
        if switch_id not in self._switches:
            self._logging.info("Switch %s has not been registered.",
                               switch_id)
            return False
        self._switches[switch_id].set_connected(True)
        self._logging.info("Switch %s connected.", switch_id)
        return True

    def switch_is_connected(self, switch_id):
        """Check if a switch is in a connected state.

        :param switch_id: Switch identifier, typically the datapath ID.
        :return: True if in connected state, False otherwise.
        """
        return self._switches[switch_id].is_connected()

    def switch_disconnect(self, switch_id):
        """Inform the policy manager that a switch has disconnected from
        the network.

        :param switch_id: Switch identifier, typically the datapath ID.
        :return: True if successful, False otherwise.
        """
        # TODO Have a configuration option specify if switch information be deleted on disconnect i.e. they get unregistered.
        self._switches[switch_id].set_connected(False)
        self._logging.info("Switch %s disconnected.", switch_id)
        return True

    def switch_exists(self, switch_id):
        """Check if a switch exists.

        :param switch_id: Switch identifier, typically the datapath ID.
        :return: True if it exists, False otherwise.
        """
        if switch_id in self._switches:
            self._logging.debug("Switch %s exists.", switch_id)
            return True
        self._logging.warning("Switch %s does not exist.", switch_id)
        return False

    def switch_assign_policy(self, switch_id, policy):
        """Assign a policy domain to a switch.

        :param switch_id: The switch to assign to.
        :param policy: The policy to assign.
        :return: True if the policy wasn't already assigned,
        False otherwise.
        """
        if self._switches[switch_id].has_policy(policy):
            self._logging.warning("Switch %s already has policy %s "
                                  "assigned.", switch_id, policy)
            return False
        self._switches[switch_id].policy_assign(policy)
        self._logging.info("Policy %s assigned to switch %s", policy,
                           switch_id)
        return True

    def switch_revoke_policy(self, switch_id, policy):
        """Revoke a policy domain from a switch.

        :param switch_id: The switch to revoke from.
        :param policy: The policy to revoke.
        :return: True if successful, False otherwise.
        """
        if not self._switches[switch_id].has_policy(policy):
            self._logging.warning("Switch %s does not have policy %s "
                                  "assigned.", switch_id, policy)
            return False
        self._switches[switch_id].policy_revoke(policy)
        self._logging.info("Policy %s revoked from switch %s", policy,
                           switch_id)
        return True

    def switch_get_policies(self, switch_id):
        """Fetch the list of policy domains assigned to a switch.

        :param switch_id: Switch identifier, typically the datapath ID.
        :return: List of policy domains.
        """
        return self._switches[switch_id].get_policies()

    def get_all_policies(self):
        """Fetch and return a dict of policies and the rules that are
        associated with them.

        :return: A dict of policies to a list of rule IDs.
        """
        return self._policy_to_rules

    def get_all_switches(self):
        """Fetch and return a dict of the IDs of connected switches
        and the policies assigned to them.

        :return: A dict of switch IDs to a list of policies.
        """
        switch_pol = {}
        for switch_id in self._switches:
            switch_pol[switch_id] = self._switches[
                switch_id].get_policies()
        return switch_pol

    def get_num_policies(self):
        """Return the number of policy domains.

        :return: The number of policy domains as an int.
        """
        return len(self._policy_to_rules)

    def get_num_switches(self):
        """Return the number of registered switches.

        :return: The number of registered switches as an int.
        """
        return len(self._switches)
