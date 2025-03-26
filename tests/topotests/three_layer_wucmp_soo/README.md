# Three Layer WUCMP SOO Test

This test suite verifies BGP Site of Origin (SOO) functionality with Weighted Unequal Cost Multi-Path (WUCMP) in a three-layer CLOS topology.

## Topology

This test uses a three-layer CLOS topology with:
- Super Spines (4): ss1, ss2, ss3, ss4  
- Spines (4): spine11, spine12, spine21, spine22
- Leafs (4): leaf11, leaf12, leaf21, leaf22

The topology is organized as follows:
1. Each leaf connects to two spines in its pod with dual links
2. Leaf11 and leaf12 connect to spine11 and spine12 (Pod 1)
3. Leaf21 and leaf22 connect to spine21 and spine22 (Pod 2)
4. Spine11 and spine21 connect to ss1 and ss3
5. Spine12 and spine22 connect to ss2 and ss4

## Test Cases

The test suite includes the following test cases:

1. **Initial State Verification**: Verifies BGP sessions are established and no SOO routes exist initially.
2. **BGP Advertise-Origin Configuration**: Configures `bgp advertise-origin` on leaf routers and verifies its effect.
3. **BGP NHG-Per-Origin Configuration**: Configures `bgp nhg-per-origin` on all routers and verifies SOO routes are created.
4. **SOO Route Details Verification**: Verifies specific details of SOO routes including their flags and associated data.
5. **Route Paths and Bitmap Verification**: Verifies the bitmap and path selection in SOO routes.
6. **Link Failure and Recovery Testing**: Simulates a link failure and recovery to test SOO route behavior.
7. **Prefix Removal Impact**: Tests how removing a prefix affects SOO routes.

## Configuration Commands

The test configures the following BGP commands:

On leaf routers:
```
router bgp
address-family ipv4 unicast
bgp advertise-origin
bgp nhg-per-origin
end
```

On spine and super spine routers:
```
router bgp
address-family ipv4 unicast
bgp nhg-per-origin
end
```

## Verification

The tests use the following commands for verification:

- `show bgp ipv4 unicast soo route json` - Show SOO routes in JSON format
- `show bgp ipv4 unicast soo route detail json` - Show detailed SOO route information in JSON format

## Running the Test

To run the test, use the following command from the FRR directory:

```bash
python3 -m pytest tests/topotests/three_layer_wucmp_soo/test_three_layer_wucmp_soo.py -v
```

To run a specific test case:

```bash
python3 -m pytest tests/topotests/three_layer_wucmp_soo/test_three_layer_wucmp_soo.py::test_specific_soo_route_details -v
```

To run all tests with detailed output:

```bash
python3 -m pytest tests/topotests/three_layer_wucmp_soo/test_three_layer_wucmp_soo.py::test_all_cases -v
``` 