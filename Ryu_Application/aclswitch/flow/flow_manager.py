# Ryu and OpenFlow modules
from ryu.ofproto import ofproto_v1_3

# Modules

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class FlowManager:
    """Class responsible for preparing messages for the controller.
    """

    # Default priority is defined to be in the middle (0x8000 in 1.3)
    # Note that for a priority p, 0 <= p <= MAX (i.e. 65535)
    OFP_MAX_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY * 2 - 1

    def __init__(self, aclswitch, logging):
        """Initialise the FlowManager object.

        :param aclswitch: ACLSwitch object.
        :param logging: ACLSWitch logging object.
        """
        self._aclswitch = aclswitch
        self._logging = logging
        self._logging.info("Initialising ACLManager...")

    def flow_deploy_multiple_rules(self, switch_id, rules):
        """Deploy a multiple ACL rules out to a single switch.

        This function currently assumes that rules will be successfully
        deployed.

        :param switch_id: The switch to deploy to.
        :param rules: List of rules to deploy.
        """
        for rule in rules:
            self._aclswitch.add_blacklist_entry(switch_id, rule)

    def flow_deploy_single_rule(self, rule, switches):
        """Deploy a single ACL rule out to a group of switches.

        This function currently assumes that rule will be successfully
        deployed.

        :param rule: The ACL rule to deploy.
        :param switches: List of switches to send the rule to.
        """
        for switch_id in switches:
            self._aclswitch.add_blacklist_entry(switch_id, rule)

    def flow_remove_single_rule(self, rule, switches):
        """Remove a single ACL rule from a group of switches.

        This function currently assumes that rule will be successfully
        removed.

        :param rule: The ACL rule to remove.
        :param switches: List of switches to removed the rule from.
        """
        for switch_id in switches:
            self._aclswitch.remove_blacklist_entry(switch_id, rule)
