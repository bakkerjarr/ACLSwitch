# Module imports

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ACLSwitchAPI:
    """API for modifying and viewing the state of ACLSwitch.
    """

    def __init__(self, logging, acl_man):
        """Initialise the API class.

        :param logging: ACLSWitch logging object.
        :param acl_man: Object that manages ACL state.
        """
        self._logging = logging
        self._logging.info("Initialising API...")
        self._acl_man = acl_man

    def create_acl_rule(self, rule):
        """Endpoint for creating an ACL rule.

        :param rule: JSON of the rule to create.
        :return: Result of the operation.
        """
        return self._acl_man.add_acl_rule(rule)
