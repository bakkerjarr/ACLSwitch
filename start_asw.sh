#!/bin/bash
# Copyright 2017 Jarrod N. Bakker
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
#title          :start_asw.sh
#description    :Start ACLSwitch on the Ryu controller.
#author         :Jarrod N. Bakker
#date           :03/04/2017
#usage          :bash start_network.sh
#========================================================================
clear ;
asw="$(pwd)/Ryu_Application/controller.py";
ryu-manager --verbose $asw ;