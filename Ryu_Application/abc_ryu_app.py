from abc import ABCMeta
from abc import abstractmethod

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ABCRyuApp:
    """Interface for Ryu applications.
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self, contr):
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
