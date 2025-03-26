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
import json
import time
from functools import partial
import pytest
import re

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.bgp import verify_bgp_convergence, verify_bgp_convergence_from_running_config


"""
test_three_layer_wucmp_soo.py: Test the BGP SOO (Site of Origin) 
feature with Weighted UCMP (Unequal Cost Multi-Path) in a three-layer CLOS topology.
"""

TOPOLOGY = """
Three-layer CLOS topology with:
- Super Spines (4): ss1, ss2, ss3, ss4
- Spines (4): spine11, spine12, spine21, spine22
- Leafs (4): leaf11, leaf12, leaf21, leaf22

The topology is organized as follows:
1. Each leaf connects to two spines in its pod with dual links
2. Leaf11 and leaf12 connect to spine11 and spine12 (Pod 1)
3. Leaf21 and leaf22 connect to spine21 and spine22 (Pod 2)
4. Spine11 and spine21 connect to ss1 and ss3
5. Spine12 and spine22 connect to ss2 and ss4

This topology tests BGP SOO (Site of Origin) with WUCMP (Weighted Unequal Cost Multi-Path).
"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd]

# Global variables
topo = None
BGP_CONVERGENCE = False

# Define these constants at the module level
NUM_OF_32_ROUTES = 5000
NUM_OF_24_ROUTES = 100
NUM_OF_AGGREGATE_ROUTES = 1
TOTAL_ROUTES_PER_LEAF = NUM_OF_32_ROUTES + NUM_OF_24_ROUTES + NUM_OF_AGGREGATE_ROUTES


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

    # add a link towards a host
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

    # add a link towards a host
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

    # add a link towards a host
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

    # add a link towards a host
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

    # Create links between spine12 and ss2 and ss4
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

        # Load sharpd config for leaf routers
        if rname.startswith("leaf"):
            logger.info("Enabling sharpd on %s" % rname)
            router.load_config(
                TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
            )

    # Initialize all routers.
    tgen.start_router()

    # Check BGP convergence
    global BGP_CONVERGENCE
    logger.info("Checking BGP convergence")
    BGP_CONVERGENCE = verify_bgp_convergence_from_running_config(tgen)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    for router in router_list.values():
        if router.has_version("<", "4.0"):
            tgen.set_error("unsupported version")

    # Check BGP establishment status for all leaf routers using JSON format
    logger.info("Verifying BGP sessions are established on all leaf routers")
    leaf_routers = ["leaf11", "leaf12", "leaf21", "leaf22"]
    for leaf_name in leaf_routers:
        leaf = tgen.gears[leaf_name]
        # Get BGP summary in JSON format
        json_output = leaf.vtysh_cmd("show bgp ipv4 unicast summary json")
        try:
            bgp_summary = json.loads(json_output)
            peers = bgp_summary.get("peers", {})

            # Verify we have the expected number of peers
            expected_peers = 4  # Each leaf should have 4 BGP neighbors
            actual_peers = len(peers)
            assert (
                actual_peers == expected_peers
            ), f"{leaf_name} has {actual_peers} BGP peers, expected {expected_peers}"

            # Verify all peers are established
            for peer_ip, peer_data in peers.items():
                state = peer_data.get("state", "")
                assert (
                    state == "Established"
                ), f"BGP session to peer {peer_ip} on {leaf_name} is {state}, expected Established"

            logger.info(
                f"All {actual_peers} BGP sessions on {leaf_name} are established"
            )
        except json.JSONDecodeError:
            assert False, f"Failed to parse JSON output from {leaf_name}"


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def configure_router(router, commands):
    """
    Configure a router with a list of commands

    Args:
        router: Router object
        commands: List of commands to execute
    """
    # Join all commands into a single command string with proper line breaks
    command_str = ""
    for cmd in commands:
        command_str += cmd + "\n"
    
    # Execute the full command string at once to maintain proper context
    router.vtysh_cmd(command_str)


def parse_soo_route_json(router, output):
    """
    Parse the JSON output from 'show bgp ipv4 unicast soo route json'

    Args:
        router: Router object
        output: String output from vtysh command

    Returns:
        dict: Parsed JSON data or None if parsing fails
    """
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        logger.error(f"Failed to parse JSON output from {router.name}")
        return None


def validate_soo_nhg(
    router, expected_soo_count, total_routes_per_leaf, validate_details=True, expected_paths=4
):
    """
    Validate SOO NHG configuration on a router

    Args:
        router: Router object
        expected_soo_count: Expected number of SOO route entries
        total_routes_per_leaf: Total number of routes per leaf
        validate_details: Whether to validate detailed SOO route properties
        expected_paths: Expected number of paths for SOO routes (default: 4)

    Returns:
        bool: True if validation passes, False otherwise
    """
    logger.info(
        f"Validating SOO NHG on {router.name} with expected {expected_soo_count} SOO entries"
    )

    # Get SOO routes
    output = router.vtysh_cmd("show bgp ipv4 unicast soo route json")
    json_data = parse_soo_route_json(router, output)

    if json_data is None:
        logger.error(f"Failed to parse JSON output from {router.name}")
        return False

    if "default" not in json_data:
        logger.error(f"Missing 'default' key in JSON output from {router.name}")
        return False

    # Count SOO routes
    soo_routes = json_data["default"]
    actual_count = len(soo_routes)

    if actual_count != expected_soo_count:
        logger.error(
            f"Expected {expected_soo_count} SOO routes on {router.name}, got {actual_count}"
        )
        return False

    logger.info(f"Found {actual_count} SOO routes on {router.name}")

    # Skip detailed validation if not requested
    if not validate_details or actual_count == 0:
        return True

    # Validate each SOO route
    for soo_route in soo_routes:
        # Validate flags
        if soo_route.get("SoORouteFlag") != "Installed":
            logger.error(
                f"SoORouteFlag not Installed for {soo_route.get('SoORoute')} on {router.name}"
            )
            return False

        if not soo_route.get("nhgValid", False):
            logger.error(
                f"nhgValid not true for {soo_route.get('SoORoute')} on {router.name}"
            )
            return False

        if soo_route.get("nhgInstallPending", True):
            logger.error(
                f"nhgInstallPending not false for {soo_route.get('SoORoute')} on {router.name}"
            )
            return False

        if soo_route.get("nhgDeletePending", True):
            logger.error(
                f"nhgDeletePending not false for {soo_route.get('SoORoute')} on {router.name}"
            )
            return False

        # Validate path count
        if soo_route.get("numPaths") != expected_paths:
            logger.error(
                f"Expected {expected_paths} paths, got {soo_route.get('numPaths')} for {soo_route.get('SoORoute')} on {router.name}"
            )
            return False

        # Validate route counts
        num_routes_with_soo = soo_route.get("numRoutesWithSoO", 0)
        num_routes_using_soo_nhg = soo_route.get("numRoutesWithSoOUsingSoONHG", 0)

        # Check that routes are using NHG
        if num_routes_with_soo != num_routes_using_soo_nhg:
            logger.error(
                f"Not all routes using SOO NHG: {num_routes_using_soo_nhg}/{num_routes_with_soo} for {soo_route.get('SoORoute')} on {router.name}"
            )
            return False

        # Check that routes with SOO and routes using SOO NHG match total_routes_per_leaf
        if num_routes_with_soo != total_routes_per_leaf:
            logger.error(
                f"Expected {total_routes_per_leaf} routes with SOO, got {num_routes_with_soo} for {soo_route.get('SoORoute')} on {router.name}"
            )
            return False

        # Check nexthopgroupId
        nhg_id = soo_route.get("nexthopgroupId", 0)
        if nhg_id < 70000000:
            logger.error(
                f"nexthopgroupId {nhg_id} less than 70000000 for {soo_route.get('SoORoute')} on {router.name}"
            )
            return False

        logger.info(
            f"SOO route {soo_route.get('SoORoute')} on {router.name} passed all validation checks"
        )

    return True


def test_initial_state():
    """
    Test case 1: Verify the initial state before any SOO configuration

    Steps:
    1. Install routes on each leaf router:
       - 5 /32 routes via sharp (leaf11: 11.0.0.0/32 - 11.0.0.4/32, etc.)
       - 5 /24 routes via static routes (leaf11: 11.1.0.0/24 - 11.1.4.0/24, etc.)
       - 1 aggregate summary route per leaf via BGP aggregate-address (leaf11: 11.0.0.0/8, etc.)
    2. Verify all routes are present in BGP tables of all routers
    3. Verify absence of SOO routes initially
    """
    tgen = get_topogen()
    global BGP_CONVERGENCE

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    if BGP_CONVERGENCE is not True:
        pytest.skip("skipped because of BGP Convergence failure")

    logger.info("Test case 1: Verifying initial state")

    # Define leaf routers and route prefixes
    leaf_routers = ["leaf11", "leaf12", "leaf21", "leaf22"]
    route_prefixes = {
        "leaf11": {
            "host_start_prefix": "11.0.0.0",
            "net_start_prefix": "11.1",
            "summary": "11.0.0.0/8",
        },
        "leaf12": {
            "host_start_prefix": "12.0.0.0",
            "net_start_prefix": "12.1",
            "summary": "12.0.0.0/8",
        },
        "leaf21": {
            "host_start_prefix": "21.0.0.0",
            "net_start_prefix": "21.1",
            "summary": "21.0.0.0/8",
        },
        "leaf22": {
            "host_start_prefix": "22.0.0.0",
            "net_start_prefix": "22.1",
            "summary": "22.0.0.0/8",
        },
    }

    num_of_32_routes = 5000
    num_of_24_routes = 100
    num_of_aggregate_routes = 1

    total_routes_per_leaf = (
        num_of_32_routes + num_of_24_routes + num_of_aggregate_routes
    )
    total_expected_routes_sent = (
        len(leaf_routers) * total_routes_per_leaf
    )  # 4 leafs * (5 /32 + 5 /24 + 1 aggregate) = 44 routes
    total_expected_routes_received = (
        len(leaf_routers) - 1
    ) * total_routes_per_leaf  # 3 other leafs * (5 /32 + 5 /24 + 1 aggregate) = 33 routes

    # Step 1: First, install all routes on all leaf routers without verifying
    logger.info("Step 1: Installing all routes on all leaf routers")
    for leaf_name in leaf_routers:
        leaf = tgen.gears[leaf_name]
        prefixes = route_prefixes[leaf_name]

        # Use loopback address as nexthop (10.0.0.x)
        # Map leaf name to loopback address
        loopback_map = {
            "leaf11": "10.0.0.11",
            "leaf12": "10.0.0.12",
            "leaf21": "10.0.0.21",
            "leaf22": "10.0.0.22",
        }
        nexthop_ip = loopback_map[leaf_name]
        logger.info(f"Using loopback address {nexthop_ip} as nexthop for {leaf_name}")

        # Install /32 routes via sharp
        logger.info(
            f"Installing {num_of_32_routes} /32 routes starting with prefix {prefixes['host_start_prefix']} on {leaf_name}"
        )
        leaf.vtysh_cmd(
            f"sharp install route {prefixes['host_start_prefix']} nexthop {nexthop_ip} {num_of_32_routes}"
        )

        # Install /24 routes via static
        logger.info(f"Installing {num_of_24_routes} /24 routes for {leaf_name}")

        prefix_base = prefixes["net_start_prefix"]

        commands = ["configure terminal"]
        for i in range(num_of_24_routes):
            commands.append(f"ip route {prefix_base}.{i}.0/24 lo")
        commands.append("exit")

        leaf.vtysh_cmd("\n".join(commands))

    # Wait for all routes to be installed and propagated
    logger.info("Waiting for all routes to be installed and propagated")
    time.sleep(10)

    # Step 2: Verify that routes are properly distributed on all leaf routers
    for leaf_name in leaf_routers:
        leaf = tgen.gears[leaf_name]
        # show bgp ipv4 unicast summary json
        json_output = leaf.vtysh_cmd("show bgp ipv4 unicast summary json")
        # Parse the JSON output
        json_data = json.loads(json_output)

        # Check that routes are properly distributed
        logger.info(f"Checking route distribution for {leaf_name}")

        # Verify each peer has the expected prefixes
        peers = json_data.get("peers", {})
        for peer_ip, peer_data in peers.items():
            pfx_received = peer_data.get("pfxRcd", 0)
            pfx_sent = peer_data.get("pfxSnt", 0)

            # Log what we found for debugging
            logger.info(
                f"{leaf_name} received {pfx_received} prefixes from peer {peer_ip} and sent {pfx_sent}"
            )

            # Each leaf should receive 33 routes from each peer (all other leaf routes)
            assert (
                pfx_received == total_expected_routes_received
            ), f"Expected {total_expected_routes_received} received prefixes from peer {peer_ip} on {leaf_name}, got {pfx_received}"

            # Each leaf should send 44 routes to each peer (all leaf routes including own)
            assert (
                pfx_sent == total_expected_routes_sent
            ), f"Expected {total_expected_routes_sent} sent prefixes to peer {peer_ip} from {leaf_name}, got {pfx_sent}"

    # Step 3: Verify absence of SOO routes initially (only on leaf11)
    logger.info("Step 4: Verifying absence of SOO routes initially on all leaf routers")
    for leaf_name in leaf_routers:
        leaf = tgen.gears[leaf_name]
        output = leaf.vtysh_cmd("show bgp ipv4 unicast soo route json")
        json_data = parse_soo_route_json(leaf, output)
        # Verify we have the expected empty state
        if "No such command" not in output:
            assert "default" in json_data, "Expected 'default' key in JSON output"
            assert (
                len(json_data["default"]) == 0
            ), "Expected empty array in 'default' section"

    logger.info("Initial state verification completed successfully")

def test_soo_nhg_configuration():
    """
    Test case 2: Test SOO NHG configuration across all network devices

    Steps:
    1. Configure ALL leaf routers (leaf11, leaf12, leaf21, leaf22) with both:
       - 'bgp advertise-origin'
       - 'bgp nhg-per-origin'
    2. Configure all super-spines and spines with 'bgp nhg-per-origin'
    3. Verify SOO route entries on leaf devices (should be number of leafs - 1)
    4. Verify SOO route entries on super-spine and spine devices (should be number of leafs)
    5. Validate SOO NHG properties on all devices
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    logger.info("Test case 2: SOO NHG Configuration Test")

    # Step 1: Configure ALL leaf routers with both bgp advertise-origin and bgp nhg-per-origin
    for leaf_name in ["leaf11", "leaf12", "leaf21", "leaf22"]:
        leaf = tgen.gears[leaf_name]
        # Use a single command string that maintains proper context
        leaf.vtysh_cmd(
            "configure terminal\n"
            "router bgp\n"
            "address-family ipv4 unicast\n"
            "bgp advertise-origin\n"
            "bgp nhg-per-origin\n"
            "end"
        )
        logger.info(f"Configured {leaf_name} with both bgp advertise-origin and bgp nhg-per-origin")

    # Step 2: Configure all super-spines and spines with bgp nhg-per-origin
    for device_name in ["ss1", "ss2", "ss3", "ss4", "spine11", "spine12", "spine21", "spine22"]:
        device = tgen.gears[device_name]
        # Use a single command string that maintains proper context
        device.vtysh_cmd(
            "configure terminal\n"
            "router bgp\n"
            "address-family ipv4 unicast\n"
            "bgp nhg-per-origin\n"
            "end"
        )
        logger.info(f"Configured {device_name} with bgp nhg-per-origin")

    # Wait for BGP to process configurations
    logger.info("Waiting for BGP to process configurations")
    time.sleep(60)  # Allow more time for BGP to converge with all devices

    # Step 3-5: Validate SOO NHG on all devices

    # Number of leaf routers
    num_leafs = 4  # leaf11, leaf12, leaf21, leaf22

    # Validate leaf devices - expect (num_leafs - 1) SOO route entries
    leaf_soo_count = num_leafs - 1  # 3
    for leaf_name in ["leaf11", "leaf12", "leaf21", "leaf22"]:
        leaf = tgen.gears[leaf_name]
        assert validate_soo_nhg(
            leaf, leaf_soo_count, TOTAL_ROUTES_PER_LEAF
        ), f"SOO NHG validation failed on {leaf_name}"
        logger.info(f"SOO NHG validation passed on {leaf_name}")

    # Validate super-spine devices - expect num_leafs SOO route entries
    super_spine_soo_count = num_leafs  # 4
    super_spine_path_count = 2
    for device_name in ["ss1", "ss2", "ss3", "ss4"]:
        device = tgen.gears[device_name]
        assert validate_soo_nhg(
            device, super_spine_soo_count, TOTAL_ROUTES_PER_LEAF, True, super_spine_path_count
        ), f"SOO NHG validation failed on {device_name}"
        logger.info(f"SOO NHG validation passed on {device_name}")
        
    # Validate spine devices - expect num_leafs SOO route entries with 4 paths
    spine_soo_count = num_leafs  # 4
    for device_name in ["spine11", "spine12", "spine21", "spine22"]:
        device = tgen.gears[device_name]
        assert validate_soo_nhg(
            device, spine_soo_count, TOTAL_ROUTES_PER_LEAF
        ), f"SOO NHG validation failed on {device_name}"
        logger.info(f"SOO NHG validation passed on {device_name}")

    logger.info("Test case 2: PASSED")
    return True


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
