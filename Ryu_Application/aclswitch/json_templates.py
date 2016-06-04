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

__author__ = "Jarrod N. Bakker"
__status__ = "Development"

"""A module for checking that JSON used to passed data is formatted
correctly.
"""

_JSON_RULE_CREATE = ("ip_src", "ip_dst", "tp_proto", "port_src",
                     "port_dst", "policy", "action", "time_enforce")
_JSON_RULE_REMOVE = ("rule_id",)
_JSON_POLICY = ("policy",)
_JSON_POLICY_ASSIGN = ("switch_id", "policy")


def check_rule_creation_json(rule):
    """Check that rule creation JSON is formatted correctly.

    :param rule: Rule JSON to check.
    :return: True if valid, False otherwise.
    """
    for key in _JSON_RULE_CREATE:
        if key not in rule.keys():
            if (key == "time_enforce" and len(rule) == len(
                    _JSON_RULE_CREATE)-1):
                return True
            return False
    if len(rule) == len(_JSON_RULE_CREATE):
        if len(rule["time_enforce"]) != 2:
            return False
        return True
    return False


def check_rule_removal_json(rule):
    """Check that rule removal JSON is formatted correctly.

    :param rule: Rule JSON to check.
    :return: True if valid, False otherwise.
    """
    if len(rule) != len(_JSON_RULE_REMOVE):
        return False
    for key in _JSON_RULE_REMOVE:
        if key not in rule.keys():
            return False
    return True


def check_policy_json(policy):
    """Check that policy domain creation JSON is formatted
    correctly. This can aso be used for policy domain removal.

    :param policy: Policy JSON to check.
    :return: True if valid, False otherwise.
    """
    if len(policy) != len(_JSON_POLICY):
        return False
    for key in _JSON_POLICY:
        if key not in policy.keys():
            return False
    return True


def check_policy_assign_json(policy_assign):
    """Check that policy domain assignment JSON is formatted
    correctly. This can also be used for messages that revoke
    assignments.

    :param policy_assign: Policy assignment JSON to check.
    :return: True if valid, False otherwise.
    """
    if len(policy_assign) != len(_JSON_POLICY_ASSIGN):
        return False
    for key in _JSON_POLICY_ASSIGN:
        if key not in policy_assign.keys():
            return False
    return True
