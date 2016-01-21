# Module imports

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class ACLSwitchLogging:
    """Logging ACLSwitch and its components.

    So far this class only prints to the terminal, printing to a file
    may be possible in the future.
    """

    def fail(self, msg):
        """Log a message indicating the failure of an operation.

        :param msg: Message to log.
        :return:
        """
        print("[-] {0}".format(msg))

    def info(self, msg):
        """Log a information message.

        :param msg: Message to log.
        """
        print("[?] {0}".format(msg))

    def success(self, msg):
        """Log a message indicating the success of an operation.

        :param msg: Message to log.
        :return:
        """
        print("[+] {0}".format(msg))

    def warning(self, msg):
        """Log a warning message.

        :param msg: Message to log.
        """
        print("[!] {0}".format(msg))
