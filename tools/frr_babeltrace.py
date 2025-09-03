#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Usage: frr_babeltrace.py trace_path

FRR pushes data into lttng tracepoints in the least overhead way possible
i.e. as binary-data/crf_arrays. These traces need to be converted into pretty
strings for easy greping etc. This script is a babeltrace python plugin for
that pretty printing.

Copyright (C) 2021  NVIDIA Corporation
Anuradha Karuppiah
"""

import ipaddress
import socket
import sys

import babeltrace


########################### common parsers - start ############################
def print_ip_addr(field_val):
    """
    pretty print "struct ipaddr"
    """
    if field_val[0] == socket.AF_INET:
        addr = [str(fv) for fv in field_val[4:8]]
        return str(ipaddress.IPv4Address(".".join(addr)))

    if field_val[0] == socket.AF_INET6:
        tmp = "".join("%02x" % fb for fb in field_val[4:])
        addr = []
        while tmp:
            addr.append(tmp[:4])
            tmp = tmp[4:]
        addr = ":".join(addr)
        return str(ipaddress.IPv6Address(addr))

    if not field_val[0]:
        return ""

    return field_val


def print_prefix_addr(field_val):
    """
    pretty print "struct prefix"
    """
    if field_val[0] == socket.AF_INET:
        addr = [str(fv) for fv in field_val[8:12]]
        return str(ipaddress.IPv4Address(".".join(addr)))

    if field_val[0] == socket.AF_INET6:
        tmp = "".join("%02x" % fb for fb in field_val[8:24])
        addr = []
        while tmp:
            addr.append(tmp[:4])
            tmp = tmp[4:]
        addr = ":".join(addr)
        return str(ipaddress.IPv6Address(addr))

    if not field_val[0]:
        return ""

    return field_val


def print_mac(field_val):
    """
    pretty print "u8 mac[6]"
    """
    return ":".join("%02x" % fb for fb in field_val)


def print_net_ipv4_addr(field_val):
    """
    pretty print ctf_integer_network ipv4
    """
    return str(ipaddress.IPv4Address(field_val))


def print_esi(field_val):
    """
    pretty print ethernet segment id, esi_t
    """
    return ":".join("%02x" % fb for fb in field_val)


def get_field_list(event):
    """
    only fetch fields added via the TP, skip metadata etc.
    """
    return event.field_list_with_scope(babeltrace.CTFScope.EVENT_FIELDS)


def parse_event(event, field_parsers):
    """
    Wild card event parser; doesn't make things any prettier
    """
    field_list = get_field_list(event)
    field_info = {}
    for field in field_list:
        if field in field_parsers:
            field_parser = field_parsers.get(field)
            field_info[field] = field_parser(event.get(field))
        else:
            field_info[field] = event.get(field)
    print(event.name, field_info)


def print_family_str(field_val):
    """
    pretty print kernel family to string
    """
    if field_val == socket.AF_INET:
        cmd_str = "ipv4"
    elif field_val == socket.AF_INET6:
        cmd_str = "ipv6"
    elif field_val == socket.AF_BRIDGE:
        cmd_str = "bridge"
    elif field_val == 128:  # RTNL_FAMILY_IPMR:
        cmd_str = "ipv4MR"
    elif field_val == 129:  # RTNL_FAMILY_IP6MR:
        cmd_str = "ipv6MR"
    else:
        cmd_str = "Invalid family"

    return cmd_str


def location_bgp_session_state_change(field_val):
    locations = {
        1: "START_TIMER_EXPIRE",
        2: "CONNECT_TIMER_EXPIRE",
        3: "HOLDTIME_EXPIRE",
        4: "ROUTEADV_TIMER_EXPIRE",
        5: "DELAY_OPEN_TIMER_EXPIRE",
        6: "BGP_OPEN_MSG_DELAYED",
        7: "Unable to get Nbr's IP Addr, waiting..",
        8: "Waiting for NHT, no path to Nbr present",
        9: "FSM_HOLDTIME_EXPIRE",
    }
    return locations.get(field_val, f"UNKNOWN({field_val})")


def bgp_status_to_string(field_val):
    statuses = {
        1: "Idle",
        2: "Connect",
        3: "Active",
        4: "OpenSent",
        5: "OpenConfirm",
        6: "Established",
        7: "Clearing",
        8: "Deleted"
    }
    return statuses.get(field_val, f"UNKNOWN({field_val})")


def bgp_event_to_string(field_val):
    events = {
        1: "BGP_Start",
        2: "BGP_Stop",
        3: "TCP_connection_open",
        4: "TCP_connection_open_w_delay",
        5: "TCP_connection_closed",
        6: "TCP_connection_open_failed",
        7: "TCP_fatal_error",
        8: "ConnectRetry_timer_expired",
        9: "Hold_Timer_expired",
        10: "KeepAlive_timer_expired",
        11: "DelayOpen_timer_expired",
        12: "Receive_OPEN_message",
        13: "Receive_KEEPALIVE_message",
        14: "Receive_UPDATE_message",
        15: "Receive_NOTIFICATION_message",
        16: "Clearing_Completed"
    }
    return events.get(field_val, f"UNKNOWN({field_val})")
############################ common parsers - end #############################


############################ evpn parsers - start #############################
def parse_frr_bgp_evpn_mac_ip_zsend(event):
    """
    bgp evpn mac-ip parser; raw format -
    ctf_array(unsigned char, mac, &pfx->prefix.macip_addr.mac,
            sizeof(struct ethaddr))
    ctf_array(unsigned char, ip, &pfx->prefix.macip_addr.ip,
            sizeof(struct ipaddr))
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {
        "ip": print_ip_addr,
        "mac": print_mac,
        "esi": print_esi,
        "vtep": print_net_ipv4_addr,
    }

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_bum_vtep_zsend(event):
    """
    bgp evpn bum-vtep parser; raw format -
    ctf_integer_network_hex(unsigned int, vtep,
            pfx->prefix.imet_addr.ip.ipaddr_v4.s_addr)

    """
    field_parsers = {"vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_nh_rmac_send(event):
    """
    bgp evpn nh-rmac parser; raw format -
    ctf_array(unsigned char, rmac, &nh->rmac, sizeof(struct ethaddr))
    """
    field_parsers = {"rmac": print_mac}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_local_es_add_zrecv(event):
    """
    bgp evpn local-es parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    """
    field_parsers = {"esi": print_esi, "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_local_es_del_zrecv(event):
    """
    bgp evpn local-es parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_local_es_evi_add_zrecv(event):
    """
    bgp evpn local-es-evi parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_local_es_evi_del_zrecv(event):
    """
    bgp evpn local-es-evi parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_es_evi_vtep_add(event):
    """
    bgp evpn remote ead evi remote vtep add; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_es_evi_vtep_del(event):
    """
    bgp evpn remote ead evi remote vtep del; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_local_ead_es_evi_route_upd(event):
    """
    bgp evpn local ead evi vtep; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_mh_local_ead_es_evi_route_del(event):
    """
    bgp evpn local ead evi vtep del; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_local_vni_add_zrecv(event):
    """
    bgp evpn local-vni parser; raw format -
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    ctf_integer_network_hex(unsigned int, mc_grp, mc_grp.s_addr)
    """
    field_parsers = {"vtep": print_net_ipv4_addr,
                     "mc_grp": print_net_ipv4_addr}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_local_l3vni_add_zrecv(event):
    """
    bgp evpn local-l3vni parser; raw format -
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    ctf_array(unsigned char, svi_rmac, svi_rmac, sizeof(struct ethaddr))
    ctf_array(unsigned char, vrr_rmac, vrr_rmac, sizeof(struct ethaddr))
    """
    field_parsers = {
        "vtep": print_net_ipv4_addr,
        "svi_rmac": print_mac,
        "vrr_rmac": print_mac,
    }

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_local_macip_add_zrecv(event):
    """
    bgp evpn local-mac-ip parser; raw format -
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac,
                     "esi": print_esi}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_local_macip_del_zrecv(event):
    """
    bgp evpn local-mac-ip del parser; raw format -
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac}

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_advertise_type5(event):
    """
    local originated type-5 route
    """
    field_parsers = {
        "ip": print_ip_addr,
        "rmac": print_mac,
        "vtep": print_net_ipv4_addr,
    }

    parse_event(event, field_parsers)


def parse_frr_bgp_evpn_withdraw_type5(event):
    """
    local originated type-5 route withdraw
    """
    field_parsers = {"ip": print_ip_addr}

    parse_event(event, field_parsers)
############################ evpn parsers - end *#############################


def parse_frr_bgp_session_state_change(event):
    field_parsers = {
        "location": location_bgp_session_state_change,
        "old_status": bgp_status_to_string,
        "new_status": bgp_status_to_string,
        "event": bgp_event_to_string
    }
    parse_event(event, field_parsers)


def parse_frr_bgp_connection_attempt(event):
    field_parsers = {
        "status": connection_status_to_string,
        "current_status": bgp_status_to_string
    }
    parse_event(event, field_parsers)


def parse_frr_bgp_fsm_event(event):
    field_parsers = {
        "event": bgp_event_to_string,
        "current_status": bgp_status_to_string,
        "next_status": bgp_status_to_string
    }
    parse_event(event, field_parsers)


def parse_frr_bgp_ifp_oper(event):
    field_parsers = {"location": lambda x: {
        1: "Intf UP",
        2: "Intf DOWN"
    }.get(x, f"Unknown BGP IFP operation location {x}")}
    parse_event(event, field_parsers)


def parse_frr_bgp_bgp_zebra_route_notify_owner(event):
    field_parsers = {
        "route_status": zapi_route_note_to_string,
        "dest_flags": parse_bgp_dest_flags,
        "prefix": print_prefix_addr
    }
    parse_event(event, field_parsers)


def parse_frr_bgp_bgp_zebra_process_local_ip_prefix_zrecv(event):
    field_parsers = {"prefix": print_prefix_addr}
    parse_event(event, field_parsers)


def parse_frr_bgp_bgp_zebra_radv_operation(event):
    field_parsers = {"location": lambda x: {
        1: "Initiating",
        2: "Terminating"
    }.get(x, f"Unknown BGP zebra RADV operation location {x}")}
    parse_event(event, field_parsers)

def parse_frr_bgp_err_str(event):
    field_parsers = {"location": lambda x: {
        1: "failed in bgp_accept",
        2: "failed in bgp_connect"
    }.get(x, f"Unknown BGP error string location {x}")}
    parse_event(event, field_parsers)


def parse_frr_bgp_ug_create_delete(event):
    field_parsers = {"operation": lambda x: {
        1: "BGP update-group create",
        2: "BGP update-group delete"
    }.get(x, f"Unknown UG create/delete operation {x}")}
    parse_event(event, field_parsers)


def parse_frr_bgp_ug_subgroup_create_delete(event):
    field_parsers = {"operation": lambda x: {
        1: "BGP update-group subgroup create",
        2: "BGP update-group subgroup delete"
    }.get(x, f"Unknown UG subgroup create/delete operation {x}")}
    parse_event(event, field_parsers)


def parse_frr_bgp_ug_subgroup_add_remove_peer(event):
    field_parsers = {"operation": lambda x: {
        1: "BGP update-group subgroup add peer",
        2: "BGP update-group subgroup remove peer"
    }.get(x, f"Unknown UG subgroup add/remove peer operation {x}")}
    parse_event(event, field_parsers)


def main():
    """
    FRR lttng trace output parser; babel trace plugin
    """
    event_parsers = {"frr_bgp:evpn_mac_ip_zsend":
                     parse_frr_bgp_evpn_mac_ip_zsend,
                     "frr_bgp:evpn_bum_vtep_zsend":
                     parse_frr_bgp_evpn_bum_vtep_zsend,
                     "frr_bgp:evpn_mh_nh_rmac_zsend":
                     parse_frr_bgp_evpn_mh_nh_rmac_send,
                     "frr_bgp:evpn_mh_local_es_add_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_add_zrecv,
                     "frr_bgp:evpn_mh_local_es_del_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_del_zrecv,
                     "frr_bgp:evpn_mh_local_es_evi_add_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_evi_add_zrecv,
                     "frr_bgp:evpn_mh_local_es_evi_del_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_evi_del_zrecv,
                     "frr_bgp:evpn_mh_es_evi_vtep_add":
                     parse_frr_bgp_evpn_mh_es_evi_vtep_add,
                     "frr_bgp:evpn_mh_es_evi_vtep_del":
                     parse_frr_bgp_evpn_mh_es_evi_vtep_del,
                     "frr_bgp:evpn_mh_local_ead_es_evi_route_upd":
                     parse_frr_bgp_evpn_mh_local_ead_es_evi_route_upd,
                     "frr_bgp:evpn_mh_local_ead_es_evi_route_del":
                     parse_frr_bgp_evpn_mh_local_ead_es_evi_route_del,
                     "frr_bgp:evpn_local_vni_add_zrecv":
                     parse_frr_bgp_evpn_local_vni_add_zrecv,
                     "frr_bgp:evpn_local_l3vni_add_zrecv":
                     parse_frr_bgp_evpn_local_l3vni_add_zrecv,
                     "frr_bgp:evpn_local_macip_add_zrecv":
                     parse_frr_bgp_evpn_local_macip_add_zrecv,
                     "frr_bgp:evpn_local_macip_del_zrecv":
                     parse_frr_bgp_evpn_local_macip_del_zrecv,
                     "frr_bgp:evpn_advertise_type5":
                     parse_frr_bgp_evpn_advertise_type5,
                     "frr_bgp:evpn_withdraw_type5":
                     parse_frr_bgp_evpn_withdraw_type5,
}

    # get the trace path from the first command line argument
    trace_path = sys.argv[1]

    # grab events
    trace_collection = babeltrace.TraceCollection()
    trace_collection.add_traces_recursive(trace_path, "ctf")

    for event in trace_collection.events:
        if event.name in event_parsers:
            event_parser = event_parsers.get(event.name)
            event_parser(event)
        else:
            parse_event(event, {})


if __name__ == "__main__":
    main()
