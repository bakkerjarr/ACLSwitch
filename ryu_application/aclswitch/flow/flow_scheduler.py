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

# Ryu and OpenFlow modules
from ryu.lib import hub

# Modules
import datetime as dt
import logging

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class FlowScheduler:
    """Class responsible for scheduling ACL rules to be deployed to
    switches.
    """

    _TIME_PAUSE = 1  # Pause time for rescheduling in seconds

    def __init__(self, logging_config, api, flow_man):
        """Initialise the FlowScheduler object.

        :param logging_config: Logging configuration dict.
        :param api: ACLSwitch API object.
        :param flow_man: FlowManager object.
        """
        self._logging = logging.getLogger(__name__)
        self._logging.setLevel(logging_config["min_lvl"])
        self._logging.propagate = logging_config["propagate"]
        self._logging.addHandler(logging_config["handler"])
        self._logging.info("Initialising FlowScheduler...")
        self._api = api
        self._flow_man = flow_man
        # The rule time queue is a list of times in 24 hour format to
        # a list of rule IDs.
        self._rule_time_queue = []
        self._rule_deploy_gthread = None

    def sched_add_rule(self, rule_id, time_enforce):
        """Insert a rule into the time queue for scheduling.

        :param rule_id: ID of the rule to schedule.
        :param time_enforce: A tuple of deployment time (24hr format)
        and enforcement duration (in seconds). Assumes that a rule can
        only be scheduled for one deployment time. Multiple times will
        be supported later.
        :return: True if successful, False otherwise.
        """
        if len(self._rule_time_queue) < 1:
            # Queue is empty so just insert the rule at the head
            self._rule_time_queue.append([rule_id])
            # Start a green thread to distribute time-based rules
            self._rule_deploy_gthread = hub.spawn(
                self._rule_deploy_alarm)
            return True

        # The queue is not empty so proceed...
        queue_head_id = self._rule_time_queue[0][0]
        queue_head_rule = self._api.acl_get_rule(queue_head_id)
        queue_head_time = dt.datetime.strptime(
            queue_head_rule.time_enforce[0], "%H:%M")
        rule_time = dt.datetime.strptime(time_enforce[0], "%H:%M")

        # Get the current time and normalise it
        cur_time = dt.datetime.strptime(
            dt.datetime.now().strftime("%H:%M"),
            "%H:%M")

        # Check if the queue head needs to be pre-empted
        if ((cur_time < queue_head_time and cur_time < rule_time <
            queue_head_time) or (queue_head_time < cur_time <
            rule_time) or (rule_time < queue_head_time < cur_time
            and rule_time < cur_time)):
            self._rule_time_queue.insert(0, [rule_id])
            hub.kill(self._rule_deploy_gthread)
            self._rule_deploy_gthread = hub.spawn(
                self._rule_deploy_alarm)
            return True

        # The rule needs to be inserted elsewhere in the queue
        len_queue = len(self._rule_time_queue)
        new_rule_time_store = rule_time
        for i in range(len_queue):
            # Reset any changes made by timedelta
            rule_time = new_rule_time_store

            rule_i = self._api.acl_get_rule(self._rule_time_queue[i][0])
            rule_i_time = dt.datetime.strptime(rule_i.time_enforce[0],
                                               "%H:%M")

            if rule_time == rule_i_time:
                self._rule_time_queue[i].append(rule_id)
                break

            if i == (len_queue - 1):
                # We have reached the end of the queue
                self._rule_time_queue.append([rule_id])
                break

            if rule_time < cur_time and rule_i_time > rule_time:
                # The new rule has a 'smaller' time value than the
                # current time but its time for scheduling has already
                # passed. This means that the rule should be scheduled
                # for tomorrow. To correct the comparisons we'll add a
                # day onto the datetime value.
                rule_time = rule_time + dt.timedelta(1)

            if i == 0 and rule_time < rule_i_time:
                self._rule_time_queue.insert(0, [rule_id])
                break

            rule_j = self._api.acl_get_rule(self._rule_time_queue[
                                                i+1][0])
            rule_j_time = dt.datetime.strptime(rule_j.time_enforce[0],
                                               "%H:%M")

            if rule_j_time < rule_i_time:
                # rule_j_time may be smaller than rule_i_time but it
                # may be scheduled for tomorrow.
                rule_j_time = rule_j_time + dt.timedelta(1)

            if rule_i_time < rule_time < rule_j_time:
                self._rule_time_queue.insert(i + 1, [rule_id])
                break
        return True

    def sched_remove_rule(self, rule_id):
        """Remove a rule from the time queue.

        :param rule_id: ID of the rule to remove from the queue.
        :return: True if successful, False otherwise.
        """
        # The first iteration is through elements in head of the queue.
        queue_head = True
        for time_period in self._rule_time_queue:
            for item in time_period:
                if item == rule_id:
                    time_period.remove(rule_id)
                    # time_period should be removed if rule_id was the
                    # only one scheduled at the time.
                    if len(time_period) < 1:
                        self._rule_time_queue.remove(time_period)
                        if queue_head:
                            # If the rule was at the head of the queue
                            # then we need to respawn the green thread.
                            hub.kill(self._rule_deploy_gthread)
                            self._rule_deploy_gthread = hub.spawn(
                                self._rule_deploy_alarm)
                    return True
            queue_head = False

    def get_time_queue(self):
        """Return the queue of scheduled

        :return: The time queue as a list of lists.
        """
        queue_formatted = []
        for time_period in self._rule_time_queue:
            time_formatted = []
            time = self._api.acl_get_rule(time_period[0]).time_enforce[0]
            time_formatted.append(time)
            time_formatted.extend(time_period)
            queue_formatted.append(time_formatted)
        return queue_formatted

    def _rule_deploy_alarm(self):
        """Distribute rules to switches when their time arises.

        An alarm is scheduled using green threads from Ryu's hub
        module. The green thread is used to trigger this function to
        distribute rules when needed.

        The next alarm is scheduled once all other necessary operations
        have been done.
        """
        while True:
            # Check that the queue is not empty
            if len(self._rule_time_queue) < 1:
                break

            rule_id = self._rule_time_queue[0][0]
            rule = self._api.acl_get_rule(rule_id)
            time_start = rule.time_enforce[0]
            # Normalise next_time
            next_scheduled = dt.datetime.strptime(time_start, "%H:%M")
            # The current time has to be normalised with the time in a
            # rule (i.e. the date of each datetime object is the same)
            # before a comparison can be made.
            current_time = dt.datetime.now().strftime("%H:%M:%S")
            normalised_current = dt.datetime.strptime(current_time,
                                                      "%H:%M:%S")
            # Compare the two times relative to the current time
            time_diff = (next_scheduled - normalised_current).seconds
            # Schedule the alarm to wait time_diff seconds
            self._logging.debug("Rule scheduler alarm waiting %s "
                                "seconds. Nxt_sch: %s\tnorm_cur: %s",
                                time_diff, next_scheduled,
                                normalised_current)
            hub.sleep(time_diff)

            # Check that the queue is not empty again
            if len(self._rule_time_queue) < 1:
                break

            # Pop the list of rules to distribute from the head of the
            # head of the queue and reinsert it at the tail.
            to_dist = self._rule_time_queue.pop(0)
            self._rule_time_queue.append(to_dist)

            # Check that the current time matches the time of a rule at
            # the top of the queue, if not then reschedule the alarm.
            rule = self._api.acl_get_rule(to_dist[0])
            time_start = rule.time_enforce[0]
            if time_start != dt.datetime.now().strftime("%H:%M"):
                continue

            # Distribute the rules that need to be distributed now
            for rule_id in to_dist:
                rule = self._api.acl_get_rule(rule_id)
                switches = self._api.policy_get_connected_switches(
                    rule.policy)
                self._flow_man.flow_deploy_single_rule(rule, switches)

            # Pause for moment to avoid flooding the switch with flow
            # mod messages. This happens because time_diff will be
            # evaluated again in the loop and it will be equal to 0
            # until a second passes.
            hub.sleep(self._TIME_PAUSE)
