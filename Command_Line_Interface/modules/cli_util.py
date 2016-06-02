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
