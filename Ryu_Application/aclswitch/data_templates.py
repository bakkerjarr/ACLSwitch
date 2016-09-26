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

"""A module for checking that data used to configure ACLSwitch is
formatted correctly.
"""

_RULE_CREATE = ("ip_src", "ip_dst", "tp_proto", "port_src",
                "port_dst", "policy", "action", "time_enforce")
_RULE_REMOVE = ("rule_id",)
_POLICY = ("policy",)
_POLICY_ASSIGN = ("switch_id", "policy")


def check_rule_creation_data(rule):
    """Check that rule creation data is formatted correctly.

    :param rule: Rule dict to check.
    :return: True if valid, False otherwise.
    """
    for key in _RULE_CREATE:
        if key not in rule.keys():
            if (key == "time_enforce" and len(rule) == len(
                    _RULE_CREATE)-1):
                return True
            return False
    if len(rule) == len(_RULE_CREATE):
        if len(rule["time_enforce"]) != 2:
            return False
        return True
    return False


def check_rule_removal_data(rule):
    """Check that rule removal data is formatted correctly.

    :param rule: Rule dict to check.
    :return: True if valid, False otherwise.
    """
    if len(rule) != len(_RULE_REMOVE):
        return False
    for key in _RULE_REMOVE:
        if key not in rule.keys():
            return False
    return True


def check_policy_data(policy):
    """Check that policy domain creation data is formatted
    correctly. This can aso be used for policy domain removal.

    :param policy: Policy dict to check.
    :return: True if valid, False otherwise.
    """
    if len(policy) != len(_POLICY):
        return False
    for key in _POLICY:
        if key not in policy.keys():
            return False
    return True


def check_policy_assign_data(policy_assign):
    """Check that policy domain assignment data is formatted
    correctly. This can also be used for messages that revoke
    assignments.

    :param policy_assign: Policy assignment dict to check.
    :return: True if valid, False otherwise.
    """
    if len(policy_assign) != len(_POLICY_ASSIGN):
        return False
    for key in _POLICY_ASSIGN:
        if key not in policy_assign.keys():
            return False
    return True
