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

from abc import ABCMeta
from abc import abstractmethod

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ABCRyuApp():
    """Interface for Ryu applications.
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        """Initialise the L2Switch application.

        :param contr: The controller abstraction.
        """
        pass

    @abstractmethod
    def get_app_name(self):
        """Return the name of the app to the caller.

        :return: Name returned as a string.
        """
        pass

    @abstractmethod
    def get_expected_handlers(self):
        """Return the event handlers that this app expects the
        controller to have.

        :return: A tuple of the OpenFlow protocol events.
        """
        pass

    @abstractmethod
    def is_supported(self):
        """Give an indication of whether or not the controller
        supports the required OpenFlow protocol events.

        :return: Status as a boolean. True if the controller can
        support the application, False otherwise.
        """
        pass

    @abstractmethod
    def _verify_contr_handlers(self):
        """Check that the controller can handle the required OpenFlow
        protocol events.

        :return: True if the controller supports all required events,
        False otherwise.
        """
        pass
