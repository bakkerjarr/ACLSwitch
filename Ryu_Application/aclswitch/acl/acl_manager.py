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
from aclswitch.acl.acl_rule_syntax import ACLRuleSyntax

# Other modules
from collections import namedtuple
from netaddr import IPAddress
import logging

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ACLManager:
    """Class that manages the state of the access control list.
    """

    ACL_ENTRY = namedtuple("ACL_ENTRY",
                           "ip_src ip_dst tp_proto port_src "
                           "port_dst policy action time_enforce")
    WILDCARD = "*"

    def __init__(self, logging_config):
        """Initialise the ACLManager object.

        :param logging_config: Logging configuration dict.
        """
        self._logging = logging.getLogger(__name__)
        self._logging.setLevel(logging_config["min_lvl"])
        self._logging.propagate = logging_config["propagate"]
        self._logging.addHandler(logging_config["handler"])
        self._logging.info("Initialising ACLManager...")
        self._rule_syntax = ACLRuleSyntax()
        # The ACL contains rule_id to ACL_ENTRY mappings.
        self._access_control_list = {}
        self._rule_id_count = 0

    def acl_rule_syntax_check(self, rule):
        """Call the syntax check for ACL rules.

        :param rule: The rule to check.
        :return: True is syntax is valid, False otherwise.
        """
        if len(self._rule_syntax.check_rule(rule)) > 0:
            self._logging.warning("Invalid rule syntax: %s", rule)
            return False
        else:
            self._logging.debug("Valid rule syntax: %s", rule)
            return True

    def acl_add_rule(self, rule):
        """Add a rule to the ACL.

        Assumes that the rule follows the correct syntax.

        :param rule: dict of the rule to add.
        :return: The ID of the new rule, None otherwise.
        """
        if "time_enforce" not in rule:
            time_enforce = "N/A"
        else:
            time_enforce = rule["time_enforce"]
        new_rule = self.ACL_ENTRY(ip_src=rule["ip_src"],
                                  ip_dst=rule["ip_dst"],
                                  tp_proto=rule["tp_proto"],
                                  port_src=rule["port_src"],
                                  port_dst=rule["port_dst"],
                                  policy=rule["policy"],
                                  action=rule["action"],
                                  time_enforce=time_enforce)
        if self._check_rule_exists(new_rule):
            self._logging.warning("ACL rule already exists: %s", rule)
            return None
        rule_id = self._rule_id_count
        self._access_control_list[rule_id] = new_rule
        self._rule_id_count += 1  # Increment to keep IDs unique
        self._logging.info("ACL rule %s created with id: %s", rule,
                           rule_id)
        return rule_id

    def acl_remove_rule(self, rule_id):
        """Remove a rule from the ACL.

        Assumes that the rule ID is valid.

        :param rule_id: ID of the rule to remove.
        :return: The rule that was removed.
        """
        rule = self.acl_get_rule(rule_id)
        del self._access_control_list[rule_id]
        self._logging.info("Removed ACL rule: %s", rule_id)
        return rule

    def acl_is_rule(self, rule_id):
        """Check if an ACL rule ID refers to a rule that exists.

        :param rule_id: ID of the rule to check.
        :return: True if the rule exists, False otherwise.
        """
        try:
            self._access_control_list[rule_id]
        except KeyError:
            self._logging.warning("ACL rule %s does not exist.", rule_id)
            return False
        self._logging.debug("ACL rule %s exists.", rule_id)
        return True

    def acl_get_rule(self, rule_id):
        """Return an ACL rule given a rule ID.

        :param rule_id: ID of a rule.
        :return: Named tuple of a rule.
        """
        rule = self._access_control_list[rule_id]
        self._logging.debug("ACL rule %s: %s", rule_id, rule)
        return rule

    def get_all_rules(self):
        """Fetch and return a dict of ACL rule IDs to their respective
        ACL rules.

        :return: A dict of rules IDs to rules.
        """
        formatted_acl = {}
        for rule_id in self._access_control_list:
            rule = self._access_control_list[rule_id]
            formatted_acl[int(rule_id)] = {"rule_id": rule_id,
                                           "ip_src": rule.ip_src,
                                           "ip_dst": rule.ip_dst,
                                           "tp_proto": rule.tp_proto,
                                           "port_src": rule.port_src,
                                           "port_dst": rule.port_dst,
                                           "policy": rule.policy,
                                           "action": rule.action,
                                           "time_enforce":
                                               rule.time_enforce}
        return formatted_acl

    def get_num_rules(self):
        """Return the number of ACL rules.

        :return: The number of ACL rules as an int.
        """
        return len(self._access_control_list)

    def _ip_to_string(self, ip_addr):
        """Returns a string representation of an IP address.

        This function is useful if a rule has an IP address has the
        form '10.1'. This function will transform it into '10.0.0.1'.
        This function supports both IPv4 and IPv6.

        :param ip_addr: The IP address to turn into a string.
        :return: The string representation of an IP address.
        """
        if ip_addr == self.WILDCARD:
            return ip_addr
        return str(IPAddress(ip_addr))

    def _compare_acl_rules(self, rule_1, rule_2):
        """Perform a check to see if two ACL rules are equivalent.

        ACL rules are considered to be equivalent if the source and
        destination IP addresses match, the transport protocol matches
        and the source and destination port numbers match.

        :param rule_1: a rule to be compared.
        :param rule_2: a rule to be compared.
        :return: True is equal, False otherwise.
        """
        return ((self._ip_to_string(rule_1.ip_src) == self._ip_to_string(
            rule_2.ip_src)) and
                (self._ip_to_string(rule_1.ip_dst) == self._ip_to_string(
                    rule_2.ip_dst)) and
                (rule_1.tp_proto == rule_2.tp_proto) and
                (rule_1.port_src == rule_2.port_src) and
                (rule_1.port_dst == rule_2.port_dst) and
                (rule_1.action == rule_2.action))

    def _check_rule_exists(self, new_rule):
        """Check if an ACL rule has already been added to the ACL.

        :param new_rule: dict of the rule to check.
        :return: True if the rule exists in the ACL already,
        False otherwise.
        """
        for rule in self._access_control_list.values():
            if self._compare_acl_rules(new_rule, rule):
                return True
        return False
