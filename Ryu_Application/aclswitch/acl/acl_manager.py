# ACLSwitch modules
from acl_rule_syntax import ACLRuleSyntax

# Other modules
from collections import namedtuple
from netaddr import IPAddress  # TODO Add to dependency list

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ACLManager:
    """Class that manages the state of the access control list.
    """

    ACL_ENTRY = namedtuple("ACL_ENTRY",
                           "ip_src ip_dst tp_proto port_src "
                           "port_dst policy time_start time_duration")
    WILDCARD = "*"

    def __init__(self, logging):
        """Initialise the ACLManager object.

        :param logging: ACLSWitch logging object.
        """
        self._logging = logging
        self._logging.info("Initialising ACLManager...")
        self._rule_syntax = ACLRuleSyntax()
        self._acl_id_count = 0
        self._access_control_list = {}  # rule_id:ACL_ENTRY

    def acl_rule_syntax_check(self, rule):
        """Call the syntax check for ACL rules.

        :param rule: The rule to check.
        :return: True is syntax is valid, False otherwise.
        """
        if len(self._rule_syntax.check_rule(rule)) > 0:
            return False
        else:
            return True

    def acl_add_rule(self, rule):
        """Add a rule to the ACL.

        Check that the rule follows the proper syntax and has not been
        entered before.

        :param rule: dict of the rule to add.
        :return: The ID of the new rule, None otherwise.
        """
        new_rule = self.ACL_ENTRY(ip_src=rule["ip_src"],
                                  ip_dst=rule["ip_dst"],
                                  tp_proto=rule["tp_proto"],
                                  port_src=rule["port_src"],
                                  port_dst=rule["port_dst"],
                                  policy=rule["policy"],
                                  time_start=0,
                                  time_duration=0)
        if self._check_rule_exists(new_rule):
            return None
        rule_id = str(self._acl_id_count)
        self._access_control_list[rule_id] = new_rule
        self._acl_id_count += 1  # Increment to keep IDs unique
        return rule_id

    def acl_get_rule(self, rule_id):
        """Return a rule given a rule ID.

        :param rule_id: ID of a rule.
        :return: Named tuple of a rule.
        """
        return self._access_control_list[rule_id]

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
                (rule_1.port_dst == rule_2.port_dst))

    def _check_rule_exists(self, new_rule):
        """Check if a rule has already been added to the ACL.

        :param new_rule: dict of the rule to check.
        :return: True if the rule exists in the ACL already,
        False otherwise.
        """
        for rule in self._access_control_list.values():
            if self._compare_acl_rules(new_rule, rule):
                return True
        return False
