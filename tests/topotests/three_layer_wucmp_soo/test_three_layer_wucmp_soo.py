#!/usr/bin/env python

#
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#


import os
import sys
from functools import partial
import pytest

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


"""
test_three_layer_wucmp_soo.py: Test.
"""

TOPOLOGY = """
tbd
"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Create the routers
    tgen.add_router("ss1")
    tgen.add_router("ss2")
    tgen.add_router("ss3")
    tgen.add_router("ss4")
    tgen.add_router("spine11")
    tgen.add_router("spine12")
    tgen.add_router("spine21")
    tgen.add_router("spine22")
    tgen.add_router("leaf11")
    tgen.add_router("leaf12")
    tgen.add_router("leaf21")
    tgen.add_router("leaf22")

    # Connect leaf11 to spine11 and spine12

    # dual links between leaf11 and spine11
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["leaf11"])
    switch.add_link(tgen.gears["spine11"])
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["leaf11"])
    switch.add_link(tgen.gears["spine11"])

    # dual links between leaf11 and spine12
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["leaf11"])
    switch.add_link(tgen.gears["spine12"])
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["leaf11"])
    switch.add_link(tgen.gears["spine12"])

    #add a link towards a host
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["leaf11"])


    # Connect leaf12 to spine 11 and spine12
    # dual links between leaf12 and spine11
    switch = tgen.add_switch("s11")
    switch.add_link(tgen.gears["leaf12"])
    switch.add_link(tgen.gears["spine11"])
    switch = tgen.add_switch("s12")
    switch.add_link(tgen.gears["leaf12"])
    switch.add_link(tgen.gears["spine11"])

    # dual links between leaf12 and spine12
    switch = tgen.add_switch("s13")
    switch.add_link(tgen.gears["leaf12"])
    switch.add_link(tgen.gears["spine12"])
    switch = tgen.add_switch("s14")
    switch.add_link(tgen.gears["leaf12"])
    switch.add_link(tgen.gears["spine12"])

    #add a link towards a host
    switch = tgen.add_switch("s15")
    switch.add_link(tgen.gears["leaf12"])

    # connect leaf21 to spine21 and spine22
    # dual links between leaf21 and spine21
    switch = tgen.add_switch("s21")
    switch.add_link(tgen.gears["leaf21"])
    switch.add_link(tgen.gears["spine21"])
    switch = tgen.add_switch("s22")
    switch.add_link(tgen.gears["leaf21"])
    switch.add_link(tgen.gears["spine21"])

    # dual links between leaf21 and spine22
    switch = tgen.add_switch("s23")
    switch.add_link(tgen.gears["leaf21"])
    switch.add_link(tgen.gears["spine22"])
    switch = tgen.add_switch("s24")
    switch.add_link(tgen.gears["leaf21"])
    switch.add_link(tgen.gears["spine22"])

    #add a link towards a host
    switch = tgen.add_switch("s25")
    switch.add_link(tgen.gears["leaf21"])
    
    # connect leaf22 to spine21 and spine22
    # dual links between leaf22 and spine21
    switch = tgen.add_switch("s31")
    switch.add_link(tgen.gears["leaf22"])
    switch.add_link(tgen.gears["spine21"])
    switch = tgen.add_switch("s32")
    switch.add_link(tgen.gears["leaf22"])
    switch.add_link(tgen.gears["spine21"])

    # dual links between leaf22 and spine22
    switch = tgen.add_switch("s33")
    switch.add_link(tgen.gears["leaf22"])
    switch.add_link(tgen.gears["spine22"])
    switch = tgen.add_switch("s34")
    switch.add_link(tgen.gears["leaf22"])
    switch.add_link(tgen.gears["spine22"])

    #add a link towards a host
    switch = tgen.add_switch("s35")
    switch.add_link(tgen.gears["leaf22"])


    # Create links between spine11 and ss1 and ss3
    # dual links between spine11 and ss1
    switch = tgen.add_switch("s41")
    switch.add_link(tgen.gears["spine11"])
    switch.add_link(tgen.gears["ss1"])
    switch = tgen.add_switch("s42")
    switch.add_link(tgen.gears["spine11"])
    switch.add_link(tgen.gears["ss1"])

    switch = tgen.add_switch("s43")
    switch.add_link(tgen.gears["spine11"])
    switch.add_link(tgen.gears["ss3"])
    switch = tgen.add_switch("s44")
    switch.add_link(tgen.gears["spine11"])
    switch.add_link(tgen.gears["ss3"])

    # Create links between spine12 and ss2 and ss3
    # dual links between spine12 and ss2
    switch = tgen.add_switch("s51")
    switch.add_link(tgen.gears["spine12"])
    switch.add_link(tgen.gears["ss2"])
    switch = tgen.add_switch("s52")
    switch.add_link(tgen.gears["spine12"])
    switch.add_link(tgen.gears["ss2"])

    # dual links between spine12 and ss4
    switch = tgen.add_switch("s53")
    switch.add_link(tgen.gears["spine12"])
    switch.add_link(tgen.gears["ss4"])
    switch = tgen.add_switch("s54")
    switch.add_link(tgen.gears["spine12"])
    switch.add_link(tgen.gears["ss4"])

    # Create links between spine21 and ss1 and ss3
    # dual links between spine21 and ss1
    switch = tgen.add_switch("61")
    switch.add_link(tgen.gears["spine21"])
    switch.add_link(tgen.gears["ss1"])
    switch = tgen.add_switch("s62")
    switch.add_link(tgen.gears["spine21"])
    switch.add_link(tgen.gears["ss1"])

    # dual links between spine21 and ss3
    switch = tgen.add_switch("63")
    switch.add_link(tgen.gears["spine21"])
    switch.add_link(tgen.gears["ss3"])
    switch = tgen.add_switch("s64")
    switch.add_link(tgen.gears["spine21"])
    switch.add_link(tgen.gears["ss3"])

    # Create links between spine22 and ss2 and ss4
    # dual links between spine22 and ss2
    switch = tgen.add_switch("71")
    switch.add_link(tgen.gears["spine22"])
    switch.add_link(tgen.gears["ss2"])
    switch = tgen.add_switch("s72")
    switch.add_link(tgen.gears["spine22"])
    switch.add_link(tgen.gears["ss2"])

    # dual links between spine22 and ss4
    switch = tgen.add_switch("73")
    switch.add_link(tgen.gears["spine22"])
    switch.add_link(tgen.gears["ss4"])
    switch = tgen.add_switch("s74")
    switch.add_link(tgen.gears["spine22"])
    switch.add_link(tgen.gears["ss4"])



def setup_module(mod):
    logger.info("Create a topology:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Starting Routers
    router_list = tgen.routers()

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()
    for router in router_list.values():
        if router.has_version("<", "4.0"):
            tgen.set_error("unsupported version")


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    "Test bgp daemon convergence"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    assert False


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
