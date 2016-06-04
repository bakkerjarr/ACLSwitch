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
import json_templates
import logging

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ConfigLoader:
    """An object to load configuration parameters.
    """

    def __init__(self, policy_file, rule_file, time_rule_file):
        self._policy_file = policy_file
        self._rule_file = rule_file
        self._time_rule_file = time_rule_file
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
        try:
            buf_in = open(self._policy_file)
            self._logging.info("Reading config from file: %s",
                               self._policy_file)
            for line in buf_in:
                if line[0] == "#" or not line.strip():
                    continue  # Skip file comments and empty lines
                try:
                    policy = json.loads(line)
                except ValueError:
                    self._logging.warning("%s could not be parsed as "
                                          "JSON.", line)
                    continue
                if not json_templates.check_policy_json(policy):
                    self._logging.warning("%s is not valid policy "
                                          "JSON", policy)
                    continue
                self._logging.debug("Read policy: %s", policy)
                policies.append(policy["policy"])
            buf_in.close()
        except IOError:
            self._logging.error("Unable to read from file: %s",
                                self._policy_file)
        return policies

    def load_rules(self):
        """Load the rules from file.

        :return: A list of rules to create.
        """
        rules = []
        try:
            buf_in = open(self._rule_file)
            self._logging.info("Reading config from file: %s",
                               self._rule_file)
            for line in buf_in:
                if line[0] == "#" or not line.strip():
                    continue  # Skip file comments and empty lines
                try:
                    rule = json.loads(line)
                except ValueError:
                    self._logging.warning("%s could not be parsed as "
                                          "JSON.", line)
                    continue
                if not json_templates.check_rule_creation_json(rule):
                    self._logging.warning("%s is not valid rule "
                                          "JSON", rule)
                    continue
                self._logging.debug("Read rule: %s", rule)
                rules.append(rule)
            buf_in.close()
        except IOError:
            self._logging.error("Unable to read from file: %s",
                                self._rule_file)
        return rules

    def load_time_rules(self):
        """Load the time enforced rules from file.

        :return: A list of time enforced rules to create.
        """
        time_rules = []
        try:
            buf_in = open(self._time_rule_file)
            self._logging.info("Reading config from file: %s",
                               self._time_rule_file)
            for line in buf_in:
                if line[0] == "#" or not line.strip():
                    continue  # Skip file comments and empty lines
                try:
                    rule = json.loads(line)
                except ValueError:
                    self._logging.warning("%s could not be parsed as "
                                          "JSON.", line)
                    continue
                if not json_templates.check_rule_creation_json(rule):
                    self._logging.warning("%s is not valid time rule "
                                          "JSON", rule)
                    continue
                self._logging.debug("Read rule: %s", rule)
                time_rules.append(rule)
            buf_in.close()
        except IOError:
            self._logging.error("Unable to read from file: %s",
                                self._rule_file)
        return time_rules
