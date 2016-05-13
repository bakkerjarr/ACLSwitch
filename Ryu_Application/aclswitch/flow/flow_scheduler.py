# Ryu and OpenFlow modules
from ryu.lib import hub

# Modules
import datetime as dt
import logging

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class FlowScheduler:
    """Class responsible for scheduling ACL rules to be deployed to
    switches.
    """

    def __init__(self, logging_config, flow_man):
        """Initialise the FlowScheduler object.

        :param logging_config: Logging configuration dict.
        :param flow_man: FlowManager object.
        """
        self._logging = logging.getLogger(__name__)
        self._logging.setLevel(logging_config["min_lvl"])
        self._logging.propagate = logging_config["propagate"]
        self._logging.addHandler(logging_config["handler"])
        self._logging.info("Initialising FlowScheduler...")
        self._flow_man = flow_man
        self._rule_time_queue = []
        self._gthread = None

    def sched_add_rule(self):
        pass

    def sched_remove_rule(self):
        pass

    def get_time_queue(self):
        """

        :return:
        """
        # TODO Comments and function renaming.
        pass

    def _rule_deploy_alarm(self):
        pass
