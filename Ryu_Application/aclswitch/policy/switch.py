# Copyright 2016 Jarrod N. Bakker
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


class Switch:
    """An abstraction of a switch.
    """

    def __init__(self, switch_id):
        """Initialise.

        Set the switch into a registered but not connected state. A
        switch has no assigned policies on creation.
        :param switch_id: Switch identifier, typically the datapath ID.
        """
        self.switch_id = switch_id
        self._registered = True
        self._connected = False
        self._policies = []

    def policy_assign(self, policy):
        """Assign a policy domain to this switch.

        :param policy: The policy to assign.
        :return: True if the policy wasn't already assigned,
        False otherwise.
        """
        if policy in self._policies:
            return False
        self._policies.append(policy)
        return True

    def policy_revoke(self, policy):
        """Revoke a policy domain from this switch.

        :param policy: The policy to revoke.
        :return: True if successful, False otherwise.
        """
        pass

    def get_policies(self):
        """Return the list of assigned policies for this switch.

        :return: List of policy domain names.
        """
        return self._policies

    def has_policy(self, policy):
        """Check if a policy has been assigned to this switch.

        :param policy: The policy to check.
        :return: True is assigned, False otherwise.
        """
        return policy in self._policies

    def is_registered(self):
        """Inform the caller if the switch is in a registered state.

        :return: the _connected field for the object.
        """
        return self._registered

    def is_connected(self):
        """Inform the caller if the switch is in a connected state.

        :return: the _connected field for the object.
        """
        return self._connected

    def set_connected(self, connected):
        """Change the connected status of a switch.

        :param connected: True if the switch is connecting, False if
        it is disconnecting.
        :return: True if successful, False otherwise.
        """
        self._connected = connected
        return True
