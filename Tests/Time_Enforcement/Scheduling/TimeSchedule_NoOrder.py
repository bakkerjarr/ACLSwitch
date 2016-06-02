#!/usr/bin/env python

#
# Test: Schedule rules around either side of the current time with no
#       particular order. This doesn't mean randomly though. 
#
# Usage: python TimeSchedule_NoOrder.py
#
# Test success: Scheduled rules appear in the correct order.
# Test failure: Scheduled rules are not in the correct order.
#
# Note:
#   - Test output can be found in TimeSchedule_NoOrder.log
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
    times = ["+20", "+30", "+40", "+50", "+35", "-40", "+80", "-100",
             "-10"]
    ast.test_schedule(test_name, filename_log_results, times)
