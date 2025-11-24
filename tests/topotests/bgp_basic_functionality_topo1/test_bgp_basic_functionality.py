#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test BGP basic functionality:

Test steps
- Create topology (setup module)
  Creating 4 routers topology, r1, r2, r3 are in IBGP and
  r3, r4 are in EBGP
- Bring up topology
- Verify for bgp to converge
- Modify/Delete and verify router-id
- Modify and verify bgp timers
- Create and verify static routes
- Modify and verify admin distance for existing static routes
- Test advertise network using network command
- Verify clear bgp
- Test bgp convergence with loopback interface
- Test advertise network using network command
- Verify routes not installed in zebra when /32 routes received
   with loopback BGP session subnet
"""
# XXX clean up in later commit to avoid conflict on rebase
# pylint: disable=C0413

import os
import sys
import time
import json
import functools
import pytest
from copy import deepcopy

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

from lib.bgp import (
    clear_bgp_and_verify,
    create_router_bgp,
    modify_as_number,
    verify_as_numbers,
    verify_bgp_convergence,
    verify_bgp_rib,
    verify_bgp_timers_and_functionality,
    verify_router_id,
)
from lib.common_config import (
    addKernelRoute,
    apply_raw_config,
    check_address_types,
    create_prefix_lists,
    create_route_maps,
    create_static_routes,
    required_linux_kernel_version,
    reset_config_on_routers,
    start_topology,
    step,
    verify_admin_distance_for_static_routes,
    verify_bgp_community,
    verify_fib_routes,
    verify_rib,
    write_test_footer,
    write_test_header,
)

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topojson import build_config_from_json
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


# Global Variable
KEEPALIVETIMER = 2
HOLDDOWNTIMER = 6
r1_ipv4_loopback = "1.0.1.0/24"
r2_ipv4_loopback = "1.0.2.0/24"
r3_ipv4_loopback = "1.0.3.0/24"
r4_ipv4_loopback = "1.0.4.0/24"
r1_ipv6_loopback = "2001:db8:f::1:0/120"
r2_ipv6_loopback = "2001:db8:f::2:0/120"
r3_ipv6_loopback = "2001:db8:f::3:0/120"
r4_ipv6_loopback = "2001:db8:f::4:0/120"
NETWORK = {
    "ipv4": ["100.1.1.1/32", "100.1.1.2/32"],
    "ipv6": ["100::1/128", "100::2/128"],
}


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=4.15")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_basic_functionality.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global ADDR_TYPES
    global BGP_CONVERGENCE
    ADDR_TYPES = check_address_types()
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


#####################################################
#
#   Testcases
#
#####################################################


def test_modify_and_delete_router_id(request):
    """Test to modify, delete and verify router-id."""

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Modify router id
    input_dict = {
        "r1": {"bgp": {"router_id": "12.12.12.12"}},
        "r2": {"bgp": {"router_id": "22.22.22.22"}},
        "r3": {"bgp": {"router_id": "33.33.33.33"}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Verifying router id once modified
    result = verify_router_id(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Delete router id
    input_dict = {
        "r1": {"bgp": {"del_router_id": True}},
        "r2": {"bgp": {"del_router_id": True}},
        "r3": {"bgp": {"del_router_id": True}},
    }
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Verifying router id once deleted
    # Once router-id is deleted, highest interface ip should become
    # router-id
    result = verify_router_id(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_bgp_config_with_4byte_as_number(request):
    """
    Configure BGP with 4 byte ASN and verify it works fine
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    input_dict = {
        "r1": {"bgp": {"local_as": 131079}},
        "r2": {"bgp": {"local_as": 131079}},
        "r3": {"bgp": {"local_as": 131079}},
        "r4": {"bgp": {"local_as": 131080}},
    }
    result = modify_as_number(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_as_numbers(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_BGP_config_with_invalid_ASN_p2(request):
    """
    Configure BGP with invalid ASN(ex - 0, reserved ASN) and verify test case
    ended up with error
    """

    tgen = get_topogen()
    global BGP_CONVERGENCE

    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to modify AS number
    input_dict = {
        "r1": {
            "bgp": {
                "local_as": 0,
            }
        },
        "r2": {
            "bgp": {
                "local_as": 0,
            }
        },
        "r3": {
            "bgp": {
                "local_as": 0,
            }
        },
        "r4": {
            "bgp": {
                "local_as": 64000,
            }
        },
    }
    result = modify_as_number(tgen, topo, input_dict)
    assert (
        result is not True
    ), "Expected BGP config is not created because of invalid ASNs: {}".format(result)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    result = verify_bgp_convergence(tgen, topo)
    if result != True:
        assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    write_test_footer(tc_name)


def test_BGP_config_with_2byteAS_and_4byteAS_number_p1(request):
    """
    Configure BGP with 4 byte and 2 byte ASN and verify BGP is converged
    """

    tgen = get_topogen()
    global BGP_CONVERGENCE

    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    result = verify_bgp_convergence(tgen, topo)
    if result != True:
        assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    # Api call to modify AS number
    input_dict = {
        "r1": {"bgp": {"local_as": 131079}},
        "r2": {"bgp": {"local_as": 131079}},
        "r3": {"bgp": {"local_as": 131079}},
        "r4": {"bgp": {"local_as": 111}},
    }
    result = modify_as_number(tgen, topo, input_dict)
    if result != True:
        assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    result = verify_as_numbers(tgen, topo, input_dict)
    if result != True:
        assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    # Api call verify whether BGP is converged
    result = verify_bgp_convergence(tgen, topo)
    if result != True:
        assert False, "Testcase " + tc_name + " :Failed \n Error: {}".format(result)

    write_test_footer(tc_name)


def test_bgp_timers_functionality(request):
    """
    Test to modify bgp timers and verify timers functionality.
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to modify BGP timerse
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r2": {
                                    "dest_link": {
                                        "r1": {
                                            "keepalivetimer": KEEPALIVETIMER,
                                            "holddowntimer": HOLDDOWNTIMER,
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, deepcopy(input_dict))
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Api call to clear bgp, so timer modification would take place
    clear_bgp_and_verify(tgen, topo, "r1")

    # Verifying bgp timers functionality
    result = verify_bgp_timers_and_functionality(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_static_routes(request):
    """Test to create and verify static routes."""

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to create static routes
    input_dict = {
        "r1": {
            "static_routes": [
                {
                    "network": "10.0.20.1/32",
                    "no_of_ip": 9,
                    "admin_distance": 100,
                    "next_hop": "10.0.0.2",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Api call to redistribute static routes
    input_dict_1 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [
                                {"redist_type": "static"},
                                {"redist_type": "connected"},
                            ]
                        }
                    }
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"
    next_hop = ["10.0.0.2", "10.0.0.5"]
    result = verify_rib(
        tgen, "ipv4", dut, input_dict, next_hop=next_hop, protocol=protocol
    )
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_admin_distance_for_existing_static_routes(request):
    """Test to modify and verify admin distance for existing static routes."""

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    input_dict = {
        "r1": {
            "static_routes": [
                {
                    "network": "10.0.20.1/32",
                    "admin_distance": 10,
                    "next_hop": "10.0.0.2",
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Verifying admin distance  once modified
    result = verify_admin_distance_for_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_advertise_network_using_network_command(request):
    """Test advertise networks using network command."""

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # Api call to advertise networks
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": "20.0.0.0/32", "no_of_network": 10},
                                {"network": "30.0.0.0/32", "no_of_network": 10},
                            ]
                        }
                    }
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r2"
    protocol = "bgp"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol=protocol)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_clear_bgp_and_verify(request):
    """
    Created few static routes and verified all routes are learned via BGP
    cleared BGP and verified all routes are intact
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    # clear ip bgp
    result = clear_bgp_and_verify(tgen, topo, "r1")
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_BGP_attributes_with_vrf_default_keyword_p0(request):
    """
    TC_9:
    Verify BGP functionality for default vrf with
    "vrf default" keyword.
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    step("Configure static routes and redistribute in BGP on R3")
    for addr_type in ADDR_TYPES:
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type][0],
                        "no_of_ip": 4,
                        "next_hop": "Null0",
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    input_dict_2 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                    "ipv6": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Create a route-map to match a specific prefix and modify"
        "BGP attributes for matched prefix"
    )
    input_dict_2 = {
        "r3": {
            "prefix_lists": {
                "ipv4": {
                    "ABC": [
                        {
                            "seqid": 10,
                            "action": "permit",
                            "network": NETWORK["ipv4"][0],
                        }
                    ]
                },
                "ipv6": {
                    "XYZ": [
                        {
                            "seqid": 100,
                            "action": "permit",
                            "network": NETWORK["ipv6"][0],
                        }
                    ]
                },
            }
        }
    }
    result = create_prefix_lists(tgen, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        if addr_type == "ipv4":
            pf_list = "ABC"
        else:
            pf_list = "XYZ"

        input_dict_6 = {
            "r3": {
                "route_maps": {
                    "BGP_ATTR_{}".format(addr_type): [
                        {
                            "action": "permit",
                            "seq_id": 10,
                            "match": {addr_type: {"prefix_lists": pf_list}},
                            "set": {
                                "aspath": {"as_num": 500, "as_action": "prepend"},
                                "localpref": 500,
                                "origin": "egp",
                                "community": {"num": "500:500", "action": "additive"},
                                "large_community": {
                                    "num": "500:500:500",
                                    "action": "additive",
                                },
                            },
                        },
                        {"action": "permit", "seq_id": 20},
                    ]
                },
                "BGP_ATTR_{}".format(addr_type): [
                    {
                        "action": "permit",
                        "seq_id": 100,
                        "match": {addr_type: {"prefix_lists": pf_list}},
                        "set": {
                            "aspath": {"as_num": 500, "as_action": "prepend"},
                            "localpref": 500,
                            "origin": "egp",
                            "community": {"num": "500:500", "action": "additive"},
                            "large_community": {
                                "num": "500:500:500",
                                "action": "additive",
                            },
                        },
                    },
                    {"action": "permit", "seq_id": 200},
                ],
            }
        }

        result = create_route_maps(tgen, input_dict_6)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Apply the route-map on R3 in outbound direction for peer R4")

    input_dict_7 = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [
                                                {
                                                    "name": "BGP_ATTR_ipv4",
                                                    "direction": "out",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3": {
                                            "route_maps": [
                                                {
                                                    "name": "BGP_ATTR_ipv6",
                                                    "direction": "out",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_7)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "verify modified attributes for specific prefix with 'vrf default'"
        "keyword on R4"
    )
    for addr_type in ADDR_TYPES:
        dut = "r4"
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type][0],
                        "vrf": "default",
                        "largeCommunity": "500:500:500",
                    }
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_rib(tgen, addr_type, dut, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        dut = "r4"
        input_dict = {
            "r3": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type][0],
                        "vrf": "default",
                        "community": "500:500",
                    }
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_rib(tgen, addr_type, dut, input_dict)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_4 = {"largeCommunity": "500:500:500", "community": "500:500"}

        result = verify_bgp_community(
            tgen, addr_type, dut, [NETWORK[addr_type][0]], input_dict_4
        )
        assert result is True, "Test case {} : Should fail \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_bgp_with_loopback_interface(request):
    """
    Test BGP with loopback interface

    Adding keys:value pair  "dest_link": "lo" and "source_link": "lo"
    peer dict of input json file for all router's creating config using
    loopback interface. Once BGP neighboship is up then verifying BGP
    convergence
    """

    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    reset_config_on_routers(tgen)

    for routerN in sorted(topo["routers"].keys()):
        for bgp_neighbor in topo["routers"][routerN]["bgp"]["address_family"]["ipv4"][
            "unicast"
        ]["neighbor"].keys():
            # Adding ['source_link'] = 'lo' key:value pair
            topo["routers"][routerN]["bgp"]["address_family"]["ipv4"]["unicast"][
                "neighbor"
            ][bgp_neighbor]["dest_link"] = {
                "lo": {
                    "source_link": "lo",
                }
            }

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    input_dict = {
        "r1": {
            "static_routes": [
                {"network": "1.0.2.17/32", "next_hop": "10.0.0.2"},
                {"network": "1.0.3.17/32", "next_hop": "10.0.0.6"},
            ]
        },
        "r2": {
            "static_routes": [
                {"network": "1.0.1.17/32", "next_hop": "10.0.0.1"},
                {"network": "1.0.3.17/32", "next_hop": "10.0.0.10"},
            ]
        },
        "r3": {
            "static_routes": [
                {"network": "1.0.1.17/32", "next_hop": "10.0.0.5"},
                {"network": "1.0.2.17/32", "next_hop": "10.0.0.9"},
                {"network": "1.0.4.17/32", "next_hop": "10.0.0.14"},
            ]
        },
        "r4": {"static_routes": [{"network": "1.0.3.17/32", "next_hop": "10.0.0.13"}]},
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Api call verify whether BGP is converged
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_bgp_ipv6_nexthop_after_interface_flap(request):
    tgen = get_topogen()
    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    tc_name = request.node.name
    write_test_header(tc_name)
    
    step("Verify BGP IPv6 convergence before interface flap")
    result = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    
    nexthop_before = r1.run('vtysh -c "show ip bgp vrf all neighbors" | grep Nexthop')
    logger.info("=" * 60 + "\nBGP Nexthops BEFORE interface flap:\n" + "-" * 60 + "\n" + nexthop_before + "\n" + "=" * 60)
    
    ifaces_output = r1.run("ip -6 addr show | grep -B2 'fd00:' | grep '^[0-9]' | awk '{print $2}' | tr -d ':'")
    interfaces = [iface.strip() for iface in ifaces_output.split('\n') if iface.strip() and iface.strip() != 'lo']
    if not interfaces:
        pytest.skip("Could not find interface with IPv6 address on r1")
    
    intf_name = interfaces[0]
    logger.info("Using interface: {} for interface flap test".format(intf_name))
    
    ipv4_output = r1.run("ip -4 addr show {} | grep 'inet ' | awk '{{print $2}}'".format(intf_name))
    ipv6_output = r1.run("ip -6 addr show {} | grep 'inet6' | grep -v 'fe80:' | awk '{{print $2}}'".format(intf_name))
    
    ipv4_addr = ipv4_output.strip() if ipv4_output.strip() else None
    ipv6_addr = ipv6_output.strip() if ipv6_output.strip() else None
    
    logger.info("Interface {} has IPv4: {} IPv6: {}".format(intf_name, ipv4_addr, ipv6_addr))
    
    r1.run("ip link set {} down".format(intf_name))
    
    step("Simulate ifreload -a: flush addresses and reconfigure interface")
    r1.run("ip addr flush dev {} scope global".format(intf_name))
    if ipv4_addr:
        r1.run("ip addr add {} dev {}".format(ipv4_addr, intf_name))
        logger.info("Re-added IPv4 address: {}".format(ipv4_addr))
    
    if ipv6_addr:
        r1.run("ip -6 addr add {} dev {}".format(ipv6_addr, intf_name))
        logger.info("Re-added IPv6 address: {}".format(ipv6_addr))
    r1.run("ip link set {} up".format(intf_name))
    
    step("Wait for BGP IPv6 to re-establish")
    result = verify_bgp_convergence(tgen, topo, addr_type="ipv6")
    assert result is True, "Testcase {} : BGP IPv6 did not reconverge after interface flap".format(tc_name)
    
    step("BGP nexthop status AFTER interface flap")
    nexthop_after = r1.run('vtysh -c "show ip bgp vrf all neighbors" | grep Nexthop')
    logger.info("=" * 60 + "\nBGP Nexthops AFTER interface flap:\n" + "-" * 60 + "\n" + nexthop_after + "\n" + "=" * 60)
    
    step("Verify IPv6 global next-hop is correctly set (not ::)")
    
    def _check_ipv6_nexthop_after():
        output = r1.vtysh_cmd("show bgp neighbors")
        
        found_empty_nexthop = False
        found_valid_nexthop = False
        
        for line in output.split('\n'):
            if "Nexthop global:" in line:
                parts = line.split("Nexthop global:")
                if len(parts) > 1:
                    nexthop = parts[1].strip()
                    logger.info("Found Nexthop global: {}".format(nexthop))
                    
                    if nexthop == "::":
                        logger.error("IPv6 global nexthop is :: after interface flap (BUG!)")
                        found_empty_nexthop = True
                    elif "fd00:" in nexthop or "2001:" in nexthop or "fe80:" in nexthop:
                        logger.info("Found valid IPv6 nexthop: {}".format(nexthop))
                        found_valid_nexthop = True
        
        if found_empty_nexthop:
            logger.error("FAIL: Found :: nexthop after interface flap!")
            return False
        elif found_valid_nexthop:
            logger.info("PASS: All nexthops are valid (no :: found)")
            return True
        else:
            logger.warning("Could not find any 'Nexthop global:' in output")
            return False
    
    test_func = functools.partial(_check_ipv6_nexthop_after)
    _, result = topotest.run_and_expect(test_func, True, count=20, wait=3)
    
    if result is not True:
        logger.error("TEST FAILED: IPv6 global nexthop became :: after interface flap!")
    
    assert result is True, "Testcase {} : IPv6 global nexthop became :: after interface flap (BUG!)".format(tc_name)
    
    logger.info("SUCCESS: IPv6 global nexthop maintained correctly after interface flap")
    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
