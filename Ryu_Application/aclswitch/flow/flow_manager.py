# Ryu and OpenFlow modules
from ryu.ofproto import ofproto_v1_3

# Modules
import logging

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class FlowManager:
    """Class responsible for preparing messages for the controller.
    """

    # Default priority is defined to be in the middle (0x8000 in 1.3)
    # Note that for a priority p, 0 <= p <= MAX (i.e. 65535)
    OFP_MAX_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY * 2 - 1

    def __init__(self, aclswitch, logging_config):
        """Initialise the FlowManager object.

        :param aclswitch: ACLSwitch object.
        :param logging_config: Logging configuration dict.
        """
        self._aclswitch = aclswitch
        self._logging = logging.getLogger(__name__)
        self._logging.setLevel(logging_config["min_lvl"])
        self._logging.propagate = logging_config["propagate"]
        self._logging.addHandler(logging_config["handler"])
        self._logging.info("Initialising ACLManager...")

    def flow_deploy_multiple_rules(self, switch_id, rules):
        """Deploy a multiple ACL rules out to a single switch.

        This function currently assumes that rules will be successfully
        deployed.

        :param switch_id: The switch to deploy to.
        :param rules: List of rules to deploy.
        """
        for rule in rules:
            self._logging.debug("Deploying rule %s to switch %s.",
                                rule, switch_id)
            self._aclswitch.add_blacklist_entry(switch_id, rule)

    def flow_deploy_single_rule(self, rule, switches):
        """Deploy a single ACL rule out to a group of switches.

        This function currently assumes that rule will be successfully
        deployed.

        :param rule: The ACL rule to deploy.
        :param switches: List of switches to send the rule to.
        """
        for switch_id in switches:
            self._logging.debug("Deploying rule %s to switch %s.",
                                rule, switch_id)
            self._aclswitch.add_blacklist_entry(switch_id, rule)

    def flow_remove_multiple_rules(self, switch_id, rules):
        """Remove multiple rules from a single switch.

        This function currently assumes that rules will be successfully
        removed.

        :param switch_id: The switch to remove the rules from.
        :param rules: List of rules to remove.
        """
        for rule in rules:
            self._logging.debug("Removing rule %s from switch %s.",
                                rule, switch_id)
            self._aclswitch.remove_blacklist_entry(switch_id, rule)

    def flow_remove_single_rule(self, rule, switches):
        """Remove a single ACL rule from a group of switches.

        This function currently assumes that rule will be successfully
        removed.

        :param rule: The ACL rule to remove.
        :param switches: List of switches to removed the rule from.
        """
        for switch_id in switches:
            self._logging.debug("Removing rule %s from switch %s.",
                                rule, switch_id)
            self._aclswitch.remove_blacklist_entry(switch_id, rule)
