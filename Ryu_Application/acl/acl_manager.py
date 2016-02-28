# ACLSwitch modules
from acl_rule_syntax import ACLRuleSyntax

# Other modules
from collections import namedtuple

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ACLManager:
    """Class that manages the state of the access control list.
    """

    ACL_ENTRY = namedtuple("ACL_ENTRY",
                           "ip_src ip_dst tp_proto port_src "
                           "port_dst policy time_start time_duration")

    def __init__(self, logging):
        """Initialise the ACLManager object.

        :param logging: ACLSWitch logging object.
        """
        self._logging = logging
        self._logging.info("Initialising ACLManager...")
        self._rule_syntax = ACLRuleSyntax()
        self._acl_id_count = 0
        self._access_control_list = {}  # rule_id:ACL_ENTRY

    def add_acl_rule(self, rule):
        result = self._rule_syntax.check_rule(rule)
        if len(result) < 1:
            return (True, result)
        else:
            return (False, result)
