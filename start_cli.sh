#!/bin/bash
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
#title          :start_cli.sh
#description    :Start the command line interface for ACLSwitch.
#author         :Jarrod N. Bakker
#date           :19/01/2016
#usage          :bash start_cli.sh
#========================================================================
clear;
cli="$(pwd)/cli/aclsw_cli.py";
python3 $cli;