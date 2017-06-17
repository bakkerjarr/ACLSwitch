#!/usr/bin/env python3
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

# Modules
import os
import sys
import unittest

# Configure the path for this Python session
script_path = os.path.dirname(os.path.realpath(__file__))
aclswitch_path = script_path[:-5]
sys.path.append(aclswitch_path)

# Unit tests
from unit_tests.acl.ut_acl_rule_syntax import TestACLRuleSyntax

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


def form_suite():
    """Create a suite of tests.

    :return: A TestSuite object with tests.
    """
    test_suite = unittest.TestSuite()
    test_suite.addTests(TestACLRuleSyntax)
    return test_suite


def run_unit_tests():
    """Run the ACLSwitch unit tests."""
    test_suite = form_suite()

    test_runner = unittest.TextTestRunner()
    test_runner.run(test_suite)


if __name__ == "__main__":
    run_unit_tests()
