// SPDX-License-Identifier: GPL-2.0-or-later
/* Tracing for zebra
 *
 * Copyright (c) 2020, 2021, NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved.
 * Donald Sharp
 */

#if !defined(__ZEBRA_TRACE_H__) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define __ZEBRA_TRACE_H__

#include "lib/trace.h"


#if defined(HAVE_LTTNG) || defined(HAVE_ZEBRA_LTTNG)

#if !defined(HAVE_LTTNG)
#undef frrtrace
#undef frrtrace_enabled
#undef frrtracelog
#define frrtrace(nargs, provider, name, ...)                                   \
       tracepoint(provider, name, ##__VA_ARGS__)
#define frrtrace_enabled(...) tracepoint_enabled(__VA_ARGS__)
#define frrtracelog(...) tracelog(__VA_ARGS__)
#endif

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER frr_zebra

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "zebra/zebra_trace.h"

#include <lttng/tracepoint.h>

#include <lib/ns.h>
#include <lib/table.h>

#include <zebra/zebra_ns.h>
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_mroute.h"
#include "zebra/rt.h"
#include "lib/stream.h"
#include "lib/vrf.h"
#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_l2_bridge_if.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/zebra_evpn_neigh.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_router.h"

#include "include/linux/neighbour.h"
#include <linux/if_bridge.h>

#define INTF_INVALID_INDEX 4294967295
#define INTF_INVALID_NAME  "not-found"
/* clang-format off */
TRACEPOINT_EVENT(
	frr_zebra,
	netlink_request_intf_addr,
	TP_ARGS(struct nlsock *, netlink_cmd,
		int, family,
		int, type,
		uint32_t, filter_mask),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, netlink_cmd, netlink_cmd)
		ctf_integer(int, family, family)
		ctf_integer(int, type, type)
		ctf_integer(uint32_t, filter_mask, filter_mask)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_interface,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_nexthop_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_interface_addr,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_route_change_read_unicast,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_rule_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)
/* clang-format off */

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_ipmr_route_stats,
	TP_ARGS(
		vrf_id_t, vrf_id),
	TP_FIELDS(
		ctf_integer(unsigned int, vrfid, vrf_id)
		ctf_string(mroute_vrf_id, "Asking for mroute information")
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_ipmr_route_stats, TRACE_INFO)

/*
 * Loc 0 -> Interface Delete
 * Loc 1 -> Interface Index Add
 * Loc 2 -> Interface Index is Shutdown. Wont wake it up
 */
TRACEPOINT_EVENT(
	frr_zebra,
	if_add_del_update,
	TP_ARGS(
		struct interface *, ifp,
        uint8_t, loc),
	TP_FIELDS(
		ctf_integer(unsigned int, vrfid, ifp->vrf->vrf_id)
		ctf_string(interface_name, ifp->name)
		ctf_integer(ifindex_t, ifindex, ifp->ifindex)
		ctf_integer(uint8_t, ifstatus, ifp->status)
		ctf_integer(uint8_t, location, loc)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, if_add_del_update, TRACE_INFO)

/*
 * Loc 1 -> Intf Update Protodown
 * Loc 2 -> Early return if already down & reason bitfield matches
 * Loc 3 -> Early return if already set queued to dplane & reason bitfield matches
 * Loc 3 -> Early return if already unset queued to dplane & reason bitfield matches
 * Loc 5 -> Intf protodown dplane change
 * Loc 6 -> Bond Mbr Protodown on Rcvd but already sent to dplane
 * Loc 7 -> Bond Mbr Protodown off  Rcvd but already sent to dplane
 * Loc 8 -> Bond Mbr reinstate protodown in the dplane
 * Loc 9 -> Intf Sweeping Protodown
 */
TRACEPOINT_EVENT(
	frr_zebra,
	if_protodown,
	TP_ARGS(
		struct interface *, ifp,
        bool, new_down,
        uint32_t, old_bitfield,
        uint32_t, new_bitfield,
        uint8_t, loc),
	TP_FIELDS(
		ctf_string(interface_name, ifp->name)
		ctf_integer(ifindex_t, ifindex, ifp->ifindex)
		ctf_integer(bool, protodown , new_down)
		ctf_integer(uint32_t, old_bitfield, old_bitfield)
		ctf_integer(uint32_t, new_bitfield, new_bitfield)
		ctf_integer(uint8_t, location, loc)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, if_protodown, TRACE_INFO)

/*
 * Loc 0 -> Zebra Interface Upd Success
 * Loc 1 -> Interface Zebra Info Ptr is NULL
 * Loc 2 -> Interface Dplane Update Failed
 */
TRACEPOINT_EVENT(
	frr_zebra,
	if_upd_ctx_dplane_result,
	TP_ARGS(
		struct interface *, ifp,
        bool, down,
        bool, pd_reason_val,
        const char*, oper,
        uint8_t, loc),
	TP_FIELDS(
		ctf_string(oper, oper)
		ctf_string(interface_name, ifp->name)
		ctf_integer(ifindex_t, ifindex, ifp->ifindex)
		ctf_integer(bool, down , down)
		ctf_integer(bool, pd_reason_val , pd_reason_val)
		ctf_integer(uint8_t, location, loc)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, if_upd_ctx, TRACE_INFO)

/*
 * Loc 0 -> DPLANE_OP_INTF_DELETE 
 * Loc 1 -> DPLANE_OP_INTF_UPDATE
 */
TRACEPOINT_EVENT(
	frr_zebra,
	if_vrf_change,
	TP_ARGS(
        ifindex_t, ifindex,
        const char*, name,
        uint32_t, tableid,
        uint8_t, loc),
	TP_FIELDS(
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_string(vrf_name, name)
		ctf_integer(uint32_t, tableid, tableid)
		ctf_integer(uint8_t, location, loc)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, if_vrf_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_br_vxlan_upd,
	TP_ARGS(
		struct interface *, ifp,
        vlanid_t, vid),
	TP_FIELDS(
		ctf_string(interface_name, ifp->name)
		ctf_integer(ifindex_t, ifindex, ifp->ifindex)
		ctf_integer(vlanid_t, access_vlan_id, vid)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, if_br_vxlan_upd, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_dplane_result,
	TP_ARGS(
        struct zebra_dplane_ctx*, ctx,
        const char*, oper,
        const char*, dplane_result,
        ns_id_t, ns_id,
		struct interface *, ifp),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, ctx, ctx)
		ctf_string(oper, oper)
		ctf_string(interface_name, ifp ? ifp->name : " ")
		ctf_integer(ifindex_t, ifindex, ifp ? ifp->ifindex : -1)
		ctf_string(dplane_result, dplane_result)
		ctf_integer(ns_id_t, ns_id, ns_id)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, if_dplane_result, TRACE_INFO)


/*
 * Loc 0 -> RTM_DELLINK
 * Loc 1 -> RTM_NEWLINK UPD: Intf has gone Down-1
 * Loc 2 -> RTM_NEWLINK UPD: Intf PTM up, Notifying clients
 * Loc 3 -> RTM_NEWLINK UPD: Intf Br changed MAC Addr
 * Loc 4 -> RTM_NEWLINK UPD: Intf has come Up
 * Loc 5 -> RTM_NEWLINK UPD: Intf has gone Down-2
 */
TRACEPOINT_EVENT(
	frr_zebra,
	if_dplane_ifp_handling,
	TP_ARGS(
        struct zebra_dplane_ctx*, ctx,
		const char*, name,
        ifindex_t, ifindex,
        uint8_t, loc),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, ctx, ctx)
		ctf_string(interface_name, name)
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_integer(uint8_t, location, loc)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, if_dplane_ifp_handling, TRACE_INFO)

/*
 * Loc 0 -> RTM_NEWLINK ADD
 * Loc 1 -> RTM_NEWLINK UPD
 */
TRACEPOINT_EVENT(
	frr_zebra,
	if_dplane_ifp_handling_new,
	TP_ARGS(
        struct zebra_dplane_ctx*, ctx,
		const char*, name,
        ifindex_t, ifindex,
        vrf_id_t, vrf_id,
		enum zebra_iftype, zif_type,
		enum zebra_slave_iftype, zif_slave_type,
        ifindex_t, master_ifindex,
        uint64_t, flags,
        uint8_t, loc),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, ctx, ctx)
		ctf_string(interface_name, name)
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		ctf_integer(uint16_t, zif_type, zif_type)
		ctf_integer(uint16_t, zif_slave_type, zif_slave_type )
		ctf_integer(ifindex_t, master_ifindex, master_ifindex)
		ctf_integer(uint64_t, flags, flags)
		ctf_integer(uint8_t, location, loc)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, if_dplane_ifp_handling_new, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	if_dplane_ifp_handling_vrf_change,
	TP_ARGS(
		const char*, name,
        ifindex_t, ifindex,
        vrf_id_t, old_vrf_id,
        vrf_id_t, vrf_id),
	TP_FIELDS(
		ctf_string(interface_name, name)
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_integer(vrf_id_t, old_vrf_id, old_vrf_id)
		ctf_integer(vrf_id_t, vrf_id, vrf_id)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, if_dplane_ifp_handling_vrf_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_ipneigh_change,
	TP_ARGS(
		struct nlmsghdr *, h,
		struct ndmsg *, ndm,
		struct interface *, ifp,
		const struct ethaddr *, mac,
		const struct ipaddr *, ip),
	TP_FIELDS(
		ctf_string(msg_type, nlmsg_type2str(h->nlmsg_type))
		ctf_integer(uint32_t, ndm_family, ndm->ndm_family)
		ctf_integer(int, ifindex, ndm->ndm_ifindex)
		ctf_string(interface_name,  ifp->name)
		ctf_integer(uint32_t, vrf_id, ifp->vrf->vrf_id)
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_ipneigh_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_parse_info,
	TP_ARGS(
		struct nlmsghdr *, h,
		const struct nlsock *, nl),
	TP_FIELDS(
		ctf_string(h, nlmsg_type2str(h->nlmsg_type) ? nlmsg_type2str(h->nlmsg_type) : "(Invalid Msg Type )")
		ctf_integer(unsigned int, nlmsglen, h->nlmsg_len)
		ctf_integer(unsigned int, nlmsgpid, h->nlmsg_pid)
		ctf_string(nl, nl->name ? nl->name : "(unknown nl name)")
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_parse_info, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_talk_info,
	TP_ARGS(
		struct nlmsghdr *, n,
		const struct nlsock *, nl),
	TP_FIELDS(
		ctf_string(n, nlmsg_type2str(n->nlmsg_type) ? nlmsg_type2str(n->nlmsg_type) : "(Invalid Msg Type )")
		ctf_integer(unsigned int, nlmsglen, n->nlmsg_len)
		ctf_integer(unsigned int, nlmsgseq, n->nlmsg_seq)
		ctf_integer(unsigned int, nlmsg_flags, n->nlmsg_flags)
		ctf_string(nl, nl->name ? nl->name : "(unknown nl name)")
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_talk_info, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_macfdb_change,
	TP_ARGS(
		struct nlmsghdr *, h,
		struct ndmsg *, ndm,
		uint32_t, nhg_id,
		vni_t, vni,
		struct ethaddr *, mac,
		struct in_addr, vtep_ip),
	TP_FIELDS(
		ctf_string(nl_msg_type,  nlmsg_type2str(h->nlmsg_type) ?
			   nlmsg_type2str(h->nlmsg_type): "(Invalid Msg Type )")
		ctf_integer(unsigned int, ndm_ifindex, ndm->ndm_ifindex)
		ctf_integer(int, ndm_state, ndm->ndm_state)
		ctf_integer(uint32_t, ndm_flags, ndm->ndm_flags)
		ctf_integer(unsigned int, nhg, nhg_id)
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_macfdb_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_neigh_update_msg_encode,
	TP_ARGS(
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		uint32_t, nhg_id,
		uint8_t, flags,
		uint16_t, state,
		uint8_t, family,
		uint8_t, type),
	TP_FIELDS(
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		ctf_integer(uint32_t, nhg, nhg_id)
		ctf_integer(uint8_t, flags, flags)
		ctf_integer(uint16_t, state, state)
		ctf_string(family, (family == AF_INET) ? "AF_INET" : "AF_INET6")
		ctf_integer(uint8_t, type, type)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_neigh_update_msg_encode, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_nexthop_msg_encode_err,
	TP_ARGS(
		uint32_t, nhg_id,
		const char *, zroute_type,
		uint8_t, location),
	TP_FIELDS(
		ctf_integer(uint32_t, nhg_id, nhg_id)
		ctf_string(zroute_type, zroute_type)
		ctf_integer(uint8_t, location, location)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_nexthop_msg_encode_err, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_nexthop_change_err,
	TP_ARGS(
		uint16_t, nlmsg_type,
		uint32_t, nhg_id),
	TP_FIELDS(
		ctf_integer(uint16_t, nlmsg_type, nlmsg_type)
		ctf_integer(uint32_t, nhg_id, nhg_id)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_nexthop_change_err, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_route_multipath_msg_encode,
	TP_ARGS(
		const struct prefix *, p,
		int, cmd,
		uint32_t, nhg_id,
		const char *, nexthop,
		size_t , datalen),
	TP_FIELDS(
		ctf_string(family, (p->family == AF_INET) ? "AF_INET" : "AF_INET6")
		ctf_array(unsigned char, pfx, p, sizeof(struct prefix))
		ctf_integer(unsigned int, pfxlen, p->prefixlen)
		ctf_integer(uint8_t, cmd, cmd)
		ctf_integer(unsigned int, nhg_id, nhg_id)
		ctf_string(nexthops, nexthop)
		ctf_integer(uint32_t, datalen, datalen)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_route_multipath_msg_encode, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_nexthop_msg_encode,
	TP_ARGS(
		const struct nexthop *, nh,
		uint32_t, nhg_id,
		char *, label_buf,
		const char *, nexthop),
	TP_FIELDS(
		ctf_integer(uint32_t, nh_index, nh->ifindex)
		ctf_integer(uint32_t, nh_vrfid, nh->vrf_id)
		ctf_integer(uint32_t, nhg_id, nhg_id)
		ctf_string(label_buf, label_buf)
		ctf_string(nexthops, nexthop)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_nexthop_msg_encode, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zsend_redistribute_route,
	TP_ARGS(
		uint32_t, cmd,
		struct zserv *, client,
		struct zapi_route, api,
		const char *, nexthop),
	TP_FIELDS(
		ctf_string(cmd, zserv_command_string(cmd))
		ctf_string(client_proto, zebra_route_string(client->proto))
		ctf_string(api_type, zebra_route_string(api.type))
		ctf_integer(uint32_t, vrfid, api.vrf_id)
		ctf_integer(unsigned int, prefix_len, api.prefix.prefixlen)
		ctf_string(nexthops, nexthop)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zsend_redistribute_route, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_ptm_bfd_dst_register,
	TP_ARGS(
		uint8_t, len),
	TP_FIELDS(
		ctf_string(reg_msg, "Register message Sent")
		ctf_integer(int, len, len)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_ptm_bfd_dst_register, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_ptm_bfd_dst_deregister,
	TP_ARGS(
		int, data_len),
	TP_FIELDS(
		ctf_string(reg_msg, "De-Register message Sent")
		ctf_integer(int, data_len, data_len)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_ptm_bfd_dst_deregister, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_ptm_bfd_client_register,
	TP_ARGS(int, data_len),
	TP_FIELDS(
		ctf_string(reg_msg, "BFD Client Register message Sent")
		ctf_integer(int, data_len, data_len)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_ptm_bfd_client_register, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_ptm_bfd_client_deregister,
	TP_ARGS(
		int, data_len),
	TP_FIELDS(
		ctf_string(reg_msg, "BFD Client De-Register message Sent")
		ctf_integer(int, data_len, data_len)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_ptm_bfd_client_deregister, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_recv_msg,
	TP_ARGS(
		const struct nlsock *, nl,
		struct msghdr *, msg),
	TP_FIELDS(
		ctf_string(netlink_recv, "netlink message recv")
		ctf_string(nl_name, nl->name)
		ctf_integer(int, msg_len, msg->msg_namelen)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_recv_msg, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_send_msg,
	TP_ARGS(
		const struct nlsock *, nl,
		struct msghdr, msg),
	TP_FIELDS(
		ctf_string(netlink_recv, "netlink message sent")
		ctf_string(nl_name, nl->name)
		ctf_integer(uint32_t, msg_len, msg.msg_namelen)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_tc_qdisc_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_tc_class_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)


TRACEPOINT_EVENT(
	frr_zebra,
	netlink_tc_filter_change,
	TP_ARGS(
		struct nlmsghdr *, header,
		ns_id_t, ns_id,
		int, startup),
	TP_FIELDS(
		ctf_integer_hex(intptr_t, header, header)
		ctf_integer(uint32_t, ns_id, ns_id)
		ctf_integer(uint32_t, startup, startup)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_send_msg, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	ip_prefix_send_to_client,
	TP_ARGS(
		vrf_id_t, vrf_id,
		uint16_t, cmd,
		struct prefix *, p),
	TP_FIELDS(
		ctf_integer(int, vrfid, vrf_id)
		ctf_integer(uint16_t, cmd, cmd)
		ctf_integer(unsigned int, prefix_len, p->prefixlen)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, ip_prefix_send_to_client, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_svi_macip_del_for_evpn_hash,
	TP_ARGS(
		struct zebra_evpn *, zevpn),
	TP_FIELDS(
		ctf_integer(int, vni, zevpn->vni)
		ctf_integer(int, flags, zevpn->flags)
		ctf_integer(uint16_t, vlan_id, zevpn->vid)
		ctf_string(vtep_ip,inet_ntoa(zevpn->local_vtep_ip))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_svi_macip_del_for_evpn_hash, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_read_mac_neigh,
	TP_ARGS(
		struct zebra_evpn *, zevpn,
		struct interface *, br_if,
	        struct zebra_vxlan_vni *, vni,
		struct interface *, vlan_if),
	TP_FIELDS(
		//TBD: mac and remote dest, since macs are SVI MAC-IP, VRR MAC-IP
		ctf_integer(int, vni, zevpn->vni)
		ctf_integer(int, brif_index, br_if->ifindex)
		ctf_string(br_if_name, br_if->name)
		ctf_integer(int, vni_access_vlan, vni->access_vlan)
		ctf_integer(int, vlanif_index, vlan_if->ifindex)
		ctf_string(vlanif_name, vlan_if->name)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_read_mac_neigh, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_send_add_to_client,
	TP_ARGS(
		struct zebra_evpn *, zevpn,
		struct zserv *, client),
	TP_FIELDS(
		ctf_integer(int, vni, zevpn->vni)
		ctf_integer(int, vrfid, zevpn->vrf_id)
		ctf_string(vtep_ip, inet_ntoa(zevpn->local_vtep_ip))
		ctf_string(client_proto, zebra_route_string(client->proto))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_send_add_to_client, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	process_remote_macip_add,
	TP_ARGS(
		vni_t, vni,
		struct zebra_evpn *, zevpn,
		struct ethaddr *, mac,
		struct ipaddr *, ip,
		struct in_addr, vtep_ip,
		esi_t *, esi,
		uint8_t , flags,
		uint32_t, seq),
	TP_FIELDS(
		ctf_string(remote_add, "Remote MACIP add from BGP")
		ctf_integer(int, vni, vni)
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(uint8_t, flags, flags)
		ctf_integer(uint32_t, seq, seq)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, process_remote_macip_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	process_remote_macip_del,
	TP_ARGS(
		vni_t, vni,
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		struct in_addr, vtep_ip),
	TP_FIELDS(
		ctf_string(remote_del, "Ignoring remote MACIP DEL VNI")
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		ctf_integer(int, vni, vni)
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, process_remote_macip_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_macip_send_msg_to_client,
	TP_ARGS(
		vni_t, vni,
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		int, state,
		uint16_t, cmd,
		uint32_t, seq,
		int, ipa_len,
		esi_t *, esi),
	TP_FIELDS(
		ctf_integer(int, vni, vni)
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		ctf_integer(int, state, state)
		ctf_string(action, (cmd == ZEBRA_MACIP_ADD) ? "Add" : "Del")
		ctf_integer(uint32_t, seq, seq)
		ctf_integer(int, ip_len, ipa_len)
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_macip_send_msg_to_client, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	vxlan_vni_state_change,
	TP_ARGS(
		uint16_t, id,
		struct zebra_if *, zif,
		vni_t, vni,
		uint8_t, state),
	TP_FIELDS(
		ctf_integer(int, id, id)
		ctf_integer(int, vni, vni)
		ctf_integer(uint8_t, state, state)
		ctf_string(zif_name, zif->ifp->name)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, vxlan_vni_state_change, TRACE_INFO)
TRACEPOINT_EVENT(
	frr_zebra,
	netlink_vlan_change,
	TP_ARGS(
		struct nlmsghdr *, h,
		struct br_vlan_msg *, bvm,
		ns_id_t, ns_id,
		struct bridge_vlan_info *, vinfo,
		uint32_t, vrange,
		uint8_t, state,
		struct interface *, ifp),
	TP_FIELDS(
		ctf_string(if_name,ifp->name)
		ctf_string(type,nlmsg_type2str(h->nlmsg_type))
		ctf_integer(int, ns_id, ns_id)
		ctf_integer(int, vid, vinfo->vid)
		ctf_integer(uint32_t, vrange, vrange)
		ctf_integer(int, bvm_index, bvm->ifindex)
		ctf_integer(int, bvm_family, bvm->family)
		ctf_integer(uint8_t, state, state)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_vlan_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_vrf_change,
	TP_ARGS(
        const char *, name,
        uint8_t, location),
	TP_FIELDS(
		ctf_string(name, name)
		ctf_integer(uint8_t, location, location)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_vrf_change, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	get_iflink_speed,
	TP_ARGS(
        const char *, ifname,
        int, error,
        const char *, strerr,
        uint8_t, location),
	TP_FIELDS(
		ctf_string(ifname, ifname)
		ctf_integer(int, error, error)
		ctf_string(strerr, strerr)
		ctf_integer(uint8_t, location, location)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, get_iflink_speed, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	z_err_string,
	TP_ARGS(
        uint8_t, location),
	TP_FIELDS(
		ctf_integer(uint8_t, location, location)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, z_err_string, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_msg_err,
	TP_ARGS(
        const char *, msg_type,
        uint32_t, data,
        uint8_t, location),
	TP_FIELDS(
		ctf_string(msg_type, msg_type)
		ctf_integer(uint32_t, data, data)
		ctf_integer(uint8_t, location, location)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_msg_err, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	netlink_intf_err,
	TP_ARGS(
        const char *, ifname,
        ifindex_t, ifindex,
        uint8_t, location),
	TP_FIELDS(
		ctf_string(ifname, ifname)
		ctf_integer(ifindex_t, ifindex, ifindex)
		ctf_integer(uint8_t, location, location)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, netlink_intf_err, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	dplane_vtep_add,
	TP_ARGS(
		const struct interface *, ifp,
		vni_t , vni,
		const struct in_addr *, ip),
	TP_FIELDS(
		ctf_string(ifp,ifp->name)
		ctf_integer(int, ifp_index, ifp->ifindex)
		ctf_integer(int, vni, vni)
		ctf_string(vtep_ip,inet_ntoa(*ip))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, dplane_vtep_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	dplane_vtep_delete,
	TP_ARGS(
		const struct interface *, ifp,
		vni_t , vni,
		const struct in_addr *, ip),
	TP_FIELDS(
		ctf_string(ifp,ifp->name)
		ctf_integer(int, ifp_index, ifp->ifindex)
		ctf_integer(int, vni, vni)
		ctf_string(vtep_ip,inet_ntoa(*ip))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, dplane_vtep_delete, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_gw_macip_del_for_evpn_hash,
	TP_ARGS(
		struct zebra_evpn *, zevpn),
	TP_FIELDS(
		ctf_integer(int, vni, zevpn->vni)
		ctf_integer(int, flags, zevpn->flags)
		ctf_integer(uint16_t, vlan_id, zevpn->vid)
		ctf_string(vtep_ip,inet_ntoa(zevpn->local_vtep_ip))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_gw_macip_del_for_evpn_hash, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_send_del_to_client,
	TP_ARGS(
		struct zserv *, client,
		struct zebra_evpn *,zevpn),
	TP_FIELDS(
		ctf_string(client, zebra_route_string(client->proto))
		ctf_integer(int, vni, zevpn->vni)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_send_del_to_client, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_process_sync_macip_add,
	TP_ARGS(
		struct zebra_evpn *, zevpn,
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		uint16_t, ipa_len,
		const esi_t *, esi,
		uint8_t, flags,
		uint32_t, seq),
	TP_FIELDS(
		ctf_integer(int, vni, zevpn->vni)
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		ctf_integer(uint16_t, ip_len, ipa_len)
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		ctf_integer(uint8_t, flags, flags)
		ctf_integer(uint32_t, seq, seq)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_process_sync_macip_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zread_route_add,
	TP_ARGS(
		struct zapi_route, api,
		char *, pfx,
		vrf_id_t , vrf_id,
		const char *, nexthop),
	TP_FIELDS(
		ctf_integer(int, api_flag, api.flags)
		ctf_integer(int, api_msg, api.message)
		ctf_integer(int, api_safi, api.safi)
		ctf_integer(unsigned int, nhg_id, api.nhgid)
		ctf_string(prefix, pfx)
		ctf_integer(int, vrf_id, vrf_id)
		ctf_string(nexthops, nexthop)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zread_route_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zread_route_del,
	TP_ARGS(
		struct zapi_route, api,
		char *, pfx,
		uint32_t, table_id),
	TP_FIELDS(
		ctf_integer(int, api_flag, api.flags)
		ctf_integer(int, api_msg, api.message)
		ctf_integer(int, api_safi, api.safi)
		ctf_string(prefix, pfx)
		ctf_integer(int, table_id, table_id)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zread_route_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zread_nhg_add,
	TP_ARGS(
		uint32_t, id,
		uint16_t, proto,
		struct nexthop_group *, nhg,
		const char *, nexthop),
	TP_FIELDS(
		ctf_integer(uint32_t, id, id)
		ctf_integer(uint16_t, proto, proto)
		ctf_integer(int, vrf_id, nhg->nexthop->vrf_id)
		ctf_integer(int, if_index, nhg->nexthop->ifindex)
		ctf_integer(int, type, nhg->nexthop->type)
		ctf_string(nexthops, nexthop)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zread_nhg_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zread_nhg_del,
	TP_ARGS(
		uint32_t, id,
		uint16_t, proto),
	TP_FIELDS(
		ctf_integer(uint32_t, id, id)
		ctf_integer(uint16_t, proto, proto)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zread_nhg_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_remote_macip_add,
	TP_ARGS(
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		vni_t, vni,
		struct in_addr, vtep_ip,
		uint8_t, flags,
		esi_t *, esi),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		ctf_integer(uint8_t, flags, flags)
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_remote_macip_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_remote_macip_del,
	TP_ARGS(
		const struct ethaddr *, mac,
		const struct ipaddr *, ip,
		vni_t, vni,
		struct in_addr, vtep_ip,
		uint16_t, ipa_len),
	TP_FIELDS(
		ctf_integer(vni_t, vni, vni)
		ctf_array(unsigned char, mac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, ip, ip,
			  sizeof(struct ipaddr))
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		ctf_integer(int, ip_len, ipa_len)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_remote_macip_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_proc_remote_nh,
	TP_ARGS(
		struct ethaddr *, mac,
		struct ipaddr *, ip,
		vrf_id_t, vrf_id),
	TP_FIELDS(
		ctf_array(unsigned char, rmac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, nh_ip, ip,
			  sizeof(struct ipaddr))
		ctf_integer(int, vrf_id, vrf_id)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_proc_remote_nh, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	evpn_dplane_remote_nh_add,
	TP_ARGS(
		struct ethaddr *, mac,
		struct ipaddr *, ip,
		vrf_id_t, vrf_id,
		const struct interface *, ifp),
	TP_FIELDS(
		ctf_array(unsigned char, rmac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, nh_ip, ip,
			  sizeof(struct ipaddr))
		ctf_integer(int, vrf_id, vrf_id)
		ctf_integer(unsigned int, ifindex, ifp->ifindex)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, evpn_dplane_remote_nh_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	evpn_dplane_remote_nh_del,
	TP_ARGS(
		struct ethaddr *, mac,
		struct ipaddr *, ip,
		const struct interface *, ifp),
	TP_FIELDS(
		ctf_array(unsigned char, rmac, mac,
			  sizeof(struct ethaddr))
		ctf_array(unsigned char, nh_ip, ip,
			  sizeof(struct ipaddr))
		ctf_integer(unsigned int, ifindex, ifp->ifindex)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, evpn_dplane_remote_nh_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_evpn_proc_remote_es,
	TP_ARGS(
		struct in_addr, vtep_ip,
		esi_t *, esi,
		uint16_t, cmd),
	TP_FIELDS(
		ctf_string(cmd, zserv_command_string(cmd))
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		ctf_array(unsigned char, esi, esi, sizeof(esi_t))
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_evpn_proc_remote_es, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	evpn_dplane_remote_rmac_add,
	TP_ARGS(
		struct zebra_mac *, zrmac,
		struct in_addr, vtep_ip,
		vni_t, vni,
		vlanid_t, vid,
		const struct interface *, vxlan_if),
	TP_FIELDS(
		ctf_array(unsigned char, rmac, &zrmac->macaddr,
			  sizeof(struct ethaddr))
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		ctf_integer(vni_t, vni, vni)
		ctf_integer(uint16_t, vlan_id, vid)
		ctf_integer(unsigned int, vxlan_if, vxlan_if->ifindex)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, evpn_dplane_remote_rmac_add, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	evpn_dplane_remote_rmac_del,
	TP_ARGS(
		struct zebra_mac *, zrmac,
		struct in_addr, vtep_ip,
		vni_t, vni,
		vlanid_t, vid,
		const struct interface *, vxlan_if),
	TP_FIELDS(
		ctf_array(unsigned char, rmac, &zrmac->macaddr,
			  sizeof(struct ethaddr))
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		ctf_integer(vni_t, vni, vni)
		ctf_integer(uint16_t, vlan_id, vid)
		ctf_integer(unsigned int, vxlan_if, vxlan_if->ifindex)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, evpn_dplane_remote_rmac_del, TRACE_INFO)

TRACEPOINT_EVENT(
	frr_zebra,
	zebra_vxlan_remote_vtep_add,
	TP_ARGS(
		struct in_addr, vtep_ip,
		vni_t, vni,
		int, flood_control),
	TP_FIELDS(
		ctf_string(vtep_ip, inet_ntoa(vtep_ip))
		ctf_integer(vni_t, vni, vni)
		ctf_integer(int, flood_control, flood_control)
		)
	)

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_vxlan_remote_vtep_add, TRACE_INFO)

TRACEPOINT_EVENT(
    frr_zebra,
    zebra_nhg_install_kernel,
    TP_ARGS(
        int, nhe),
    TP_FIELDS(
        ctf_integer(int, nexthop_id, nhe)
        )
   )

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_install_kernel, TRACE_INFO)

TRACEPOINT_EVENT(
    frr_zebra,
    zebra_nhg_uninstall_kernel_rejlist_del,
    TP_ARGS(
        int, nhe),
    TP_FIELDS(
        ctf_integer(int, nexthop_id, nhe)
        )
   )

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_uninstall_kernel_rejlist_del, TRACE_INFO)

TRACEPOINT_EVENT(
    frr_zebra,
    zebra_nhg_uninstall_kernel,
    TP_ARGS(
        int, nhe),
    TP_FIELDS(
        ctf_integer(int, nexthop_id, nhe)
        )
   )

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_uninstall_kernel, TRACE_INFO)

TRACEPOINT_EVENT(
    frr_zebra,
    zebra_nhg_dplane_result,
    TP_ARGS(
        struct zebra_dplane_ctx *, ctx,
        const char *, op,
        int, id,
        const char *, status),
    TP_FIELDS(
        ctf_integer_hex(intptr_t, ctx, ctx)
        ctf_string(op, op)
        ctf_integer(int, nexthop_id, id)
        ctf_string(status, status)
        )
   )

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_dplane_result, TRACE_INFO)

TRACEPOINT_EVENT(
    frr_zebra,
    zebra_interface_nhg_reinstall,
    TP_ARGS(
        const struct interface *, ifp),
    TP_FIELDS(
        ctf_string(ifp, ifp->name)
        ctf_integer(unsigned int, ifindex, ifp->ifindex)
        )
   )

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_interface_nhg_reinstall, TRACE_INFO)

TRACEPOINT_EVENT(
    frr_zebra,
    zebra_nhg_id_counter_wrapped,
    TP_ARGS(
        int, id),
    TP_FIELDS(
        ctf_integer(int, counter_id, id)
        )
   )

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_id_counter_wrapped, TRACE_INFO)

TRACEPOINT_EVENT(
    frr_zebra,
    zebra_nhg_dep,
    TP_ARGS(
        int, nhe_id,
        int, dep_id),
    TP_FIELDS(
        ctf_integer(int, nhe_id, nhe_id)
        ctf_integer(int, dep_id, dep_id)
        )
   )

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_dep, TRACE_INFO)

TRACEPOINT_EVENT(
    frr_zebra,
    zebra_nhg_intf_lkup_failed,
    TP_ARGS(
        int, ifindex,
        int, vrf_id,
        struct nhg_hash_entry *, nhe),
    TP_FIELDS(
        ctf_integer(int, if_index, ifindex)
        ctf_integer(int, vrf_id, vrf_id)
        ctf_integer_hex(intptr_t, nhe_id, nhe->id)
        )
   )

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_intf_lkup_failed, TRACE_INFO)

TRACEPOINT_EVENT(
    frr_zebra,
    nhg_ctx_process_new_nhe,
    TP_ARGS(
        int, id),
    TP_FIELDS(
        ctf_integer(int, nhe_id, id)
        )
   )

TRACEPOINT_LOGLEVEL(frr_zebra, nhg_ctx_process_new_nhe, TRACE_INFO)

TRACEPOINT_EVENT(
    frr_zebra,
    zebra_nhg_nhe2grp_internal_failure,
    TP_ARGS(
        int, id),
    TP_FIELDS(
        ctf_integer(int, depend_id, id)
        )
   )

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_nhe2grp_internal_failure, TRACE_INFO)

TRACEPOINT_EVENT(
    frr_zebra,
    zebra_nhg_free_nhe_refcount,
    TP_ARGS(
        int, id,
        int, refcount),
    TP_FIELDS(
        ctf_integer_hex(intptr_t, nhe_id, id)
        ctf_integer(int, ref_cnt, refcount)
        )
    )

TRACEPOINT_LOGLEVEL(frr_zebra, zebra_nhg_free_nhe_refcount, TRACE_INFO)

TRACEPOINT_EVENT(
    frr_zebra,
    rib_process_subq_dequeue,
    TP_ARGS(
        int, qindex),
    TP_FIELDS(
        ctf_integer(int, qindex, qindex)
        )
   )

TRACEPOINT_LOGLEVEL(frr_zebra, rib_process_subq_dequeue, TRACE_INFO)

/* clang-format on */
#include <lttng/tracepoint-event.h>

#endif /* HAVE_LTTNG */

#endif /* __ZEBRA_TRACE_H__ */
