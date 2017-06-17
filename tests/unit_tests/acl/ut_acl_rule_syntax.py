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
import unittest

# ACLSwitch Modules
from ryu_application.aclswitch.acl.acl_rule_syntax import ACLRuleSyntax

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class TestACLRuleSyntax(unittest.TestCase):
    """A collection of unit tests for the ACLRuleSyntax class.
    """

    def setUp(self):
        self.ars = ACLRuleSyntax()

    def test_duration_max(self):
        max_duration = self.ars._MAX_DURATION
        self.assertTrue(self.ars._check_duration(max_duration))
        self.assertFalse(self.ars._check_duration(max_duration + 1))

    def test_duration_min(self):
        min_duration = self.ars._MIN_DURATION
        self.assertTrue(self.ars._check_duration(min_duration))
        self.assertFalse(self.ars._check_duration(min_duration - 1))

    def test_duration_valid(self):
        valid_duration = (self.ars._MAX_DURATION +
                          self.ars._MIN_DURATION)/2
        self.assertTrue(self.ars._check_duration(valid_duration))

if __name__ == "__main__":
    unittest.main()
