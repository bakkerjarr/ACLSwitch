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

# Module imports
import json
import data_templates
import logging
import sys
import yaml

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ConfigLoader:
    """An object to load configuration parameters.
    """

    _PD_CONF_KEYS = ["policy_domains", "pd_assignments"]
    _ACL_RULE_CONF_KEYS = ["acl_rules"]

    def __init__(self, policy_file, rule_file):
        """Initialise ACLSwitch configuration loader.

        :param policy_file: Path to the Policy Domain declaration and
        assignment file.
        :param rule_file: Path to the ACL rule declaration file.
        """
        self._policy_file = policy_file
        self._rule_file = rule_file
        # Logging configuration
        min_lvl = logging.DEBUG
        console_handler = logging.StreamHandler()
        console_handler.setLevel(min_lvl)
        #formatter = logging.Formatter("%(asctime)s - %(levelname)s - "
        #                              "%(name)s - %(message)s")
        formatter = logging.Formatter("%(levelname)s - %(name)s - %("
                                      "message)s")
        console_handler.setFormatter(formatter)
        self._logging_config = {"min_lvl": min_lvl, "propagate":
                                False, "handler": console_handler}
        self._logging = logging.getLogger(__name__)
        self._logging.setLevel(self._logging_config["min_lvl"])
        self._logging.propagate = self._logging_config["propagate"]
        self._logging.addHandler(self._logging_config["handler"])

    def get_logging_config(self):
        """Return the configuration for logging.

        :return: Dict with the configuration.
        """
        return self._logging_config

    def load_policies(self):
        """Load the policy domains from file.

        :return: A list of policies to create.
        """
        policies = []
        pd_assignments = []
        try:
            self._logging.info("Loading config from file: %s",
                               self._policy_file)
            with open(self._policy_file) as buf_in:
                pd_yaml = yaml.load(buf_in)
        except IOError:
            self._logging.error("Unable to read from file: %s",
                                self._policy_file)
            return policies  # We should return an empty list
        # Perform a configuration file key check
        if not self._check_conf_keys(pd_yaml, self._PD_CONF_KEYS,
                                     self._policy_file):
            sys.exit("Please correct configuration file: {0}".format(
                self._policy_file))
        # Copy declared policy domains into a list, if there are any
        if pd_yaml["policy_domains"] is not None:
            for policy in pd_yaml["policy_domains"]:
                if policy is not None:
                    self._logging.debug("Reading Policy Domain: %s",
                                        policy)
                    policies.append(policy)
        # Read in policy assignments, if there are any
        if pd_yaml["pd_assignments"] is not None:
            for assignment in pd_yaml["pd_assignments"]:
                if assignment is not None:
                    self._logging.debug("Reading Policy Domain "
                                        "assignment: %s",
                                        str(assignment))
                    pd_assignments.append(pd_assignments)
        return policies  # TODO return PD assignments

    def load_rules(self):
        """Load the rules from file.

        :return: A list of rules to create.
        """
        rules = []
        try:
            self._logging.info("Loading config from file: %s",
                               self._rule_file)
            with open(self._rule_file) as buf_in:
                rule_yaml = yaml.load(buf_in)
        except IOError:
            self._logging.error("Unable to read from file: %s",
                                self._rule_file)
            return rules  # We should return an empty list
        # Perform a configuration file key check
        if not self._check_conf_keys(rule_yaml, self._ACL_RULE_CONF_KEYS,
                                     self._rule_file):
            sys.exit("Please correct configuration file: {0}".format(
                self._rule_file))
        # Copy declared ACL rules into a list, if there are any
        if rule_yaml["acl_rules"] is not None:
            for rule in rule_yaml["acl_rules"]:
                if not data_templates.check_rule_creation_json(rule):
                    self._logging.warning("%s is not valid rule: ", rule)
                    continue
                self._logging.debug("Reading ACL rule: %s", rule)
                rules.append(rule)
        return rules

    def _check_conf_keys(self, conf_yaml, conf_keys, conf_file):
        """Check that some parsed configuration YAML contains the
        expected high-level keys.

        :param conf_yaml: The parsed YAML to check.
        :param conf_keys: The expected high-level YAML keys.
        :param conf_file: The file the configuration was read from.
        :return: True if all keys exist, False otherwise.
        """
        # Does the config file contain the expected keys?
        if conf_yaml is None:
            self._logging.critical("The following keys were not in %s: "
                                   "%s", conf_file, ", ".join(conf_keys))
            return False
        missing_keys = []
        for key in conf_keys:
            if key not in conf_yaml:
                missing_keys.append(key)
        if len(missing_keys) != 0:
            self._logging.critical("The following keys were not in %s: "
                                   "%s", conf_file, ", ".join(
                                                           missing_keys))
            return False
        return True
