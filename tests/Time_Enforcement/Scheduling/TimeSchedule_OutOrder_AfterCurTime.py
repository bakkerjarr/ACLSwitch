#!/usr/bin/env python

#
# Test: Schedule rules after the current time in no particular oder.
#
# Usage: python TimeSchedule_OutOrder_AfterCurTime.py
#
# Test success: Scheduled rules appear in the correct order.
# Test failure: Scheduled rules are not in the correct order.
#
# Note:
#   - Test output can be found in TimeSchedule_OutOrder_AfterCurTime_results.log
#
#   - The script assumes that the syntax for the REST commands are
#     legal.
#
# Author: Jarrod N. Bakker
#

import acl_scheduling_test as ast
import os

if __name__ == "__main__":
    test_name = os.path.basename(__file__)
    filename_log_results = test_name[:-3] + "_results.log"

    # Begin the test
    times = ["+5", "+150", "+20", "+40", "+35", "+1", "+80", "+110",
             "+10", "+1000"]
    ast.test_schedule(test_name, filename_log_results, times)
