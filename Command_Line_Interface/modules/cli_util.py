#!/usr/bin/env python3

__author__ = "Jarrod N. Bakker"
__status__ = "development"


MSG_CON_ERR = "Connection error: "
MSG_HTTP_ERR = "HTTP error: "
MSG_TIMEOUT = "Connection timeout: "
MSG_REDIRECT_ERR = "Redirect error: "


def parse(args):
    """Split a string into an argument tuple by whitespace.

    :param args: The argument to parse.
    :return: The separate arguments in a tuple.
    """
    return tuple(args.split())
