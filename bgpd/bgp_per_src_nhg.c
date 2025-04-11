/* BGP Per Source Nexthop Group
 * Copyright (C) 2013 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "frrevent.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "log.h"
#include "memory.h"
#include "nexthop.h"
#include "vrf.h"
#include "filter.h"
#include "nexthop_group.h"
#include "wheel.h"
#include "lib/jhash.h"
#include "workqueue.h"
#include <config.h>

#include "bgpd/bgp_trace.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_nhg.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_per_src_nhg.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_evpn.h"

extern struct zclient *zclient;
#define PER_SRC_NHG_TABLE_SIZE 8

DEFINE_MTYPE_STATIC(BGPD, BGP_PER_SRC_NHG, "BGP Per Source NHG Info");
DEFINE_MTYPE_STATIC(BGPD, BGP_DEST_SOO_HE, "BGP Dest SOO hash entry Info");
DEFINE_MTYPE_STATIC(BGPD, BGP_SOO_NHG_NEXTHOP_CACHE, "BGP SOO NHG nexthop cache Info");

/* Extern APIs */
extern int make_prefix(int afi, struct bgp_path_info *pi, struct prefix *p);
extern struct in6_addr *bgp_path_info_to_ipv6_nexthop(struct bgp_path_info *path,
						      ifindex_t *ifindex);

/* Static */
static void bgp_per_src_nhg_del_send(struct bgp_per_src_nhg_hash_entry *nhe);
static void bgp_per_src_nhg_timer_slot_run(void *item);
static void bgp_per_src_nhg_move_to_zebra_nhid_cb(struct hash_bucket *bucket, void *ctx);
static void bgp_soo_zebra_route_install(struct bgp_per_src_nhg_hash_entry *nhe,
					struct bgp_dest *dest);

struct bgp_peer_clear_route_ctx {
	struct peer *peer;
	struct bgp_table *table;
};

/* SOO timer wheel APIs */
static unsigned int bgp_per_src_nhg_slot_key(const void *item)
{
	const struct bgp_per_src_nhg_hash_entry *nhe = item;
	const struct ipaddr *ip = &nhe->ip;

	if (IS_IPADDR_V4(ip))
		return jhash_1word(ip->ipaddr_v4.s_addr, 0);

	return jhash2(ip->ipaddr_v6.s6_addr32, array_size(ip->ipaddr_v6.s6_addr32), 0);
}

static void bgp_start_soo_timer(struct bgp *bgp, struct bgp_per_src_nhg_hash_entry *soo_entry)
{
	if (!bgp->per_src_nhg_soo_timer_wheel)
		return;

	if (!soo_entry->soo_timer_running) {
		/*
                 * if soo timer is not already running, insert it in to the
                 * timer wheel
                 */
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug("bgp vrf %s per src nhg soo %pIA %s add to timer wheel",
				   bgp->name_pretty, &soo_entry->ip,
				   get_afi_safi_str(soo_entry->afi, soo_entry->safi, false));

		frrtrace(1, frr_bgp, per_src_nhg_soo_timer_start, soo_entry);
		wheel_add_item(bgp->per_src_nhg_soo_timer_wheel, soo_entry);
		soo_entry->soo_timer_running = true;
	}
}

static void bgp_stop_soo_timer(struct bgp *bgp, struct bgp_per_src_nhg_hash_entry *soo_entry)
{
	if (!bgp->per_src_nhg_soo_timer_wheel)
		return;

	if (soo_entry->soo_timer_running) {
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug("bgp vrf %s per src nhg soo %pIA %s remove from timer wheel",
				   bgp->name_pretty, &soo_entry->ip,
				   get_afi_safi_str(soo_entry->afi, soo_entry->safi, false));
		frrtrace(1, frr_bgp, per_src_nhg_soo_timer_stop, soo_entry);
		wheel_remove_item(bgp->per_src_nhg_soo_timer_wheel, soo_entry);
		soo_entry->soo_timer_running = false;
	}
}

void bgp_per_src_nhg_soo_timer_wheel_init(struct bgp *bgp)
{
	if (!bgp->per_src_nhg_soo_timer_wheel) {
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug("bgp vrf %s per src nhg soo timer wheel init total "
				   "period %u ms slots %u",
				   bgp->name_pretty, bgp->per_src_nhg_convergence_timer,
				   BGP_PER_SRC_NHG_SOO_TIMER_WHEEL_SLOTS);

		frrtrace(2, frr_bgp, per_src_nhg_soo_timer_wheel_init,
			 bgp->per_src_nhg_convergence_timer, BGP_PER_SRC_NHG_SOO_TIMER_WHEEL_SLOTS);

		bgp->per_src_nhg_soo_timer_wheel =
			wheel_init(bm->master, bgp->per_src_nhg_convergence_timer,
				   BGP_PER_SRC_NHG_SOO_TIMER_WHEEL_SLOTS, bgp_per_src_nhg_slot_key,
				   bgp_per_src_nhg_timer_slot_run,
				   "BGP per src NHG SoO Timer Wheel");
	}
}

void bgp_per_src_nhg_soo_timer_wheel_delete(struct bgp *bgp)
{
	if (bgp->per_src_nhg_soo_timer_wheel) {
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug("bgp vrf %s per src nhg soo timer wheel delete",
				   bgp->name_pretty);

		wheel_delete(bgp->per_src_nhg_soo_timer_wheel);
		bgp->per_src_nhg_soo_timer_wheel = NULL;
	}
}

/* SOO Nexthop Cache APIs */
int bgp_nhg_nexthop_cache_compare(const struct bgp_nhg_nexthop_cache *a,
				  const struct bgp_nhg_nexthop_cache *b)
{
	if (a->ifindex < b->ifindex)
		return -1;
	if (a->ifindex > b->ifindex)
		return 1;

	return prefix_cmp(&a->prefix, &b->prefix);
}

static struct bgp_nhg_nexthop_cache *bnc_nhg_new(struct bgp_nhg_nexthop_cache_head *tree,
						 struct prefix *prefix, ifindex_t ifindex)
{
	struct bgp_nhg_nexthop_cache *bnc;

	bnc = XCALLOC(MTYPE_BGP_SOO_NHG_NEXTHOP_CACHE, sizeof(struct bgp_nhg_nexthop_cache));
	bnc->prefix = *prefix;
	bnc->ifindex = ifindex;
	bnc->tree = tree;
	bgp_nhg_nexthop_cache_add(tree, bnc);

	return bnc;
}

static void bnc_nhg_free(struct bgp_nhg_nexthop_cache *bnc)
{
	bgp_nhg_nexthop_cache_del(bnc->tree, bnc);
	XFREE(MTYPE_BGP_SOO_NHG_NEXTHOP_CACHE, bnc);
}

static void bgp_nhg_nexthop_cache_reset(struct bgp_nhg_nexthop_cache_head *tree)
{
	struct bgp_nhg_nexthop_cache *bnc;

	while (bgp_nhg_nexthop_cache_count(tree) > 0) {
		bnc = bgp_nhg_nexthop_cache_first(tree);

		bnc_nhg_free(bnc);
	}
}

static struct bgp_nhg_nexthop_cache *bnc_nhg_find(struct bgp_nhg_nexthop_cache_head *tree,
						  struct prefix *prefix, ifindex_t ifindex)
{
	struct bgp_nhg_nexthop_cache bnc = {};

	if (!tree)
		return NULL;

	bnc.prefix = *prefix;
	bnc.ifindex = ifindex;
	return bgp_nhg_nexthop_cache_find(tree, &bnc);
}

/* 'Route with SOO' Hash Table APIs */
static void *bgp_dest_soo_alloc(void *p)
{
	struct bgp_dest_soo_hash_entry *tmp_dest_he = p;
	struct bgp_dest_soo_hash_entry *dest_he;

	dest_he = XCALLOC(MTYPE_BGP_DEST_SOO_HE, sizeof(struct bgp_dest_soo_hash_entry));
	*dest_he = *tmp_dest_he;

	return ((void *)dest_he);
}

static struct bgp_dest_soo_hash_entry *bgp_dest_soo_find(struct bgp_per_src_nhg_hash_entry *nhe,
							 const struct prefix *p)
{
	struct bgp_dest_soo_hash_entry tmp;
	struct bgp_dest_soo_hash_entry *dest_he;

	memset(&tmp, 0, sizeof(tmp));
	prefix_copy(&tmp.p, p);
	dest_he = hash_lookup(nhe->route_with_soo_table, &tmp);

	return dest_he;
}

static uint32_t bgp_dest_soo_hash_keymake(const void *p)
{
	const struct bgp_dest_soo_hash_entry *dest_he = p;
	return prefix_hash_key((void *)&dest_he->p);
}

static bool bgp_dest_soo_cmp(const void *p1, const void *p2)
{
	const struct bgp_dest_soo_hash_entry *dest_he1 = p1;
	const struct bgp_dest_soo_hash_entry *dest_he2 = p2;

	if (dest_he1 == NULL && dest_he2 == NULL)
		return true;

	if (dest_he1 == NULL || dest_he2 == NULL)
		return false;

	return (prefix_cmp(&dest_he1->p, &dest_he2->p) == 0);
}

static void bgp_dest_soo_init(struct bgp_per_src_nhg_hash_entry *nhe)
{
	char buf[INET6_ADDRSTRLEN];

	ipaddr2str(&nhe->ip, buf, sizeof(buf));

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per source nhg %s %s route with soo hash init",
			   nhe->bgp->name_pretty, buf, get_afi_safi_str(nhe->afi, nhe->safi, false));
	nhe->route_with_soo_table = hash_create_size(PER_SRC_NHG_TABLE_SIZE,
						     bgp_dest_soo_hash_keymake, bgp_dest_soo_cmp,
						     "BGP route with SOO hash table");
}

static void bgp_dest_soo_free(struct bgp_dest_soo_hash_entry *dest_he)
{
	bf_free(dest_he->bgp_pi_bitmap);
	XFREE(MTYPE_BGP_DEST_SOO_HE, dest_he);
}

static void bgp_dest_soo_flush_entry(struct bgp_dest_soo_hash_entry *dest_he)
{
	struct bgp_per_src_nhg_hash_entry *nhe = dest_he->nhe;

	if (CHECK_FLAG(dest_he->flags, DEST_USING_SOO_NHGID)) {
		nhe->route_with_soo_use_nhid_cnt--;
		UNSET_FLAG(dest_he->flags, DEST_USING_SOO_NHGID);
	}

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
		char buf[INET6_ADDRSTRLEN];
		char pfxprint[PREFIX2STR_BUFFER];
		ipaddr2str(&nhe->ip, buf, sizeof(buf));
		prefix2str(&dest_he->p, pfxprint, sizeof(pfxprint));
		zlog_debug("bgp vrf %s per src nhg %s %s dest soo %s flush", nhe->bgp->name_pretty,
			   buf, get_afi_safi_str(nhe->afi, nhe->safi, false), pfxprint);
	}
}

static void bgp_dest_soo_flush_cb(struct hash_bucket *bucket, void *ctxt)
{
	struct bgp_dest_soo_hash_entry *dest_he = (struct bgp_dest_soo_hash_entry *)bucket->data;

	bgp_dest_soo_flush_entry(dest_he);
}

static void bgp_dest_soo_finish(struct bgp_per_src_nhg_hash_entry *nhe)
{
	char buf[INET6_ADDRSTRLEN];

	ipaddr2str(&nhe->ip, buf, sizeof(buf));

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per source nhg %s %s dest soo hash finish",
			   nhe->bgp->name_pretty, buf, get_afi_safi_str(nhe->afi, nhe->safi, false));
	hash_iterate(nhe->route_with_soo_table,
		     (void (*)(struct hash_bucket *, void *))bgp_dest_soo_flush_cb, NULL);
	hash_clean(nhe->route_with_soo_table, (void (*)(void *))bgp_dest_soo_free);
}

/* SOO Hash Table APIs */
static void *bgp_per_src_nhg_alloc(void *p)
{
	struct bgp_per_src_nhg_hash_entry *tmp_nhe = p;
	struct bgp_per_src_nhg_hash_entry *nhe;

	nhe = XCALLOC(MTYPE_BGP_PER_SRC_NHG, sizeof(struct bgp_per_src_nhg_hash_entry));
	*nhe = *tmp_nhe;
	return ((void *)nhe);
}

struct bgp_per_src_nhg_hash_entry *bgp_per_src_nhg_find(struct bgp *bgp, struct ipaddr *ip,
							afi_t afi, safi_t safi)
{
	struct bgp_per_src_nhg_hash_entry tmp = { 0 };
	struct bgp_per_src_nhg_hash_entry *nhe;

	if (!bgp->per_src_nhg_table[afi][safi])
		return NULL;

	memcpy(&tmp.ip, ip, sizeof(struct ipaddr));
	nhe = hash_lookup(bgp->per_src_nhg_table[afi][safi], &tmp);

	return nhe;
}

static unsigned int bgp_per_src_nhg_hash_keymake(const void *p)
{
	const struct bgp_per_src_nhg_hash_entry *nhe = p;
	const struct ipaddr *ip = &nhe->ip;

	return jhash_1word(ip->ipaddr_v4.s_addr, 0);
}

static bool bgp_per_src_nhg_cmp(const void *p1, const void *p2)
{
	const struct bgp_per_src_nhg_hash_entry *nhe1 = p1;
	const struct bgp_per_src_nhg_hash_entry *nhe2 = p2;

	if (nhe1 == NULL && nhe2 == NULL)
		return true;

	if (nhe1 == NULL || nhe2 == NULL)
		return false;

	return (ipaddr_cmp(&nhe1->ip, &nhe2->ip) == 0);
}

void bgp_per_src_nhg_init(struct bgp *bgp, afi_t afi, safi_t safi)
{
	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per source nhg hash init", bgp->name_pretty);
	bgp->per_src_nhg_table[afi][safi] =
		hash_create_size(PER_SRC_NHG_TABLE_SIZE, bgp_per_src_nhg_hash_keymake,
				 bgp_per_src_nhg_cmp, "BGP Per Source NHG hash table");
}

static void bgp_per_src_nhe_free(struct bgp_per_src_nhg_hash_entry *nhe)
{
	bf_free(nhe->bgp_soo_route_installed_pi_bitmap);
	bf_free(nhe->bgp_soo_route_selected_pi_bitmap);
	XFREE(MTYPE_BGP_PER_SRC_NHG, nhe);
}

static void bgp_per_src_nhg_flush_entry(struct bgp_per_src_nhg_hash_entry *nhe)
{
	bgp_nhg_nexthop_cache_reset(&nhe->nhg_nexthop_cache_table);
	bgp_dest_soo_finish(nhe);
	bgp_stop_soo_timer(nhe->bgp, nhe);
	if (CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID))
		bgp_per_src_nhg_del_send(nhe);

	bgp_nhg_id_free(PER_SRC_NHG, nhe->nhg_id);

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
		char buf[INET6_ADDRSTRLEN];
		ipaddr2str(&nhe->ip, buf, sizeof(buf));
		zlog_debug("bgp vrf %s per src nhg %s %s flush", nhe->bgp->name_pretty, buf,
			   get_afi_safi_str(nhe->afi, nhe->safi, false));
	}
}

static void bgp_per_src_nhg_flush_cb(struct hash_bucket *bucket, void *arg)
{
	struct bgp_dest *dest;
	struct bgp_per_src_nhg_hash_entry *nhe = (struct bgp_per_src_nhg_hash_entry *)bucket->data;

	UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID);
	SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_DEL_PENDING);
	hash_iterate(nhe->route_with_soo_table,
		     (void (*)(struct hash_bucket *, void *))bgp_per_src_nhg_move_to_zebra_nhid_cb,
		     NULL);

	/* 'SOO route' dest */
	dest = nhe->dest;
	if (dest && CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL)) {
		bgp_soo_zebra_route_install(nhe, dest);
		UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL);
	}
}

void bgp_per_src_nhg_finish(struct bgp *bgp, afi_t afi, safi_t safi)
{
	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg finish", bgp->name_pretty);
	hash_iterate(bgp->per_src_nhg_table[afi][safi],
		     (void (*)(struct hash_bucket *, void *))bgp_per_src_nhg_flush_cb, NULL);
}

static void bgp_per_src_nhg_stop_cb(struct hash_bucket *bucket, void *ctxt)
{
	struct bgp_per_src_nhg_hash_entry *nhe = (struct bgp_per_src_nhg_hash_entry *)bucket->data;

	if (nhe)
		bgp_per_src_nhg_flush_entry(nhe);
}

void bgp_per_src_nhg_stop(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg stop", bgp->name_pretty);

	FOREACH_AFI_SAFI (afi, safi) {
		if (bgp->per_src_nhg_table[afi][safi]) {
			hash_iterate(bgp->per_src_nhg_table[afi][safi],
				     (void (*)(struct hash_bucket *, void *))bgp_per_src_nhg_stop_cb,
				     NULL);
			hash_clean(bgp->per_src_nhg_table[afi][safi],
				   (void (*)(void *))bgp_per_src_nhe_free);
		}
	}
}

/* Check if 'SoO route' installed pi bitmap is a subset of 'route with SoO' pi
 * bitmap
 */
static bool is_soo_rt_installed_pi_subset_of_rt_with_soo_pi(
	struct bgp_dest_soo_hash_entry *bgp_dest_with_soo_entry)
{
	if (!bgp_dest_with_soo_entry)
		return false;

	bitfield_t rt_with_soo_pi_bitmap = bgp_dest_with_soo_entry->bgp_pi_bitmap;
	bitfield_t soo_rt_installed_pi_bitmap =
		bgp_dest_with_soo_entry->nhe->bgp_soo_route_installed_pi_bitmap;

	return bf_is_subset(&soo_rt_installed_pi_bitmap, &rt_with_soo_pi_bitmap);
}

/* Check if 'SoO route' selected pi bitmap is a subset of 'route with SoO' pi
 * bitmap
 */
static bool is_soo_rt_selected_pi_subset_of_rt_with_soo_pi(
	struct bgp_dest_soo_hash_entry *bgp_dest_with_soo_entry)
{
	if (!bgp_dest_with_soo_entry)
		return false;

	bitfield_t rt_with_soo_pi_bitmap = bgp_dest_with_soo_entry->bgp_pi_bitmap;
	bitfield_t soo_rt_selected_pi_bitmap =
		bgp_dest_with_soo_entry->nhe->bgp_soo_route_selected_pi_bitmap;

	return bf_is_subset(&soo_rt_selected_pi_bitmap, &rt_with_soo_pi_bitmap);
}

static void bgp_per_src_nhg_subset_check_cb(struct hash_bucket *bucket, void *ctx)
{
	bool *is_subset_of_all_routes = ctx;
	struct bgp_dest_soo_hash_entry *route_with_soo_entry =
		(struct bgp_dest_soo_hash_entry *)bucket->data;

	if (route_with_soo_entry) {
		if (CHECK_FLAG(route_with_soo_entry->flags, DEST_USING_SOO_NHGID)) {
			/* Check if 'SoO route' pi bitmap a subset of 'route
			 * with SoO' */
			if (!is_soo_rt_selected_pi_subset_of_rt_with_soo_pi(route_with_soo_entry))
				*is_subset_of_all_routes = false;
		}
	}
}

/* Check if SOO route path info bitmap is subset of path info bitmap of "all"
 * the routes with SOO. This function walks all the "route with SOO" and checks
 * if "SOO route" path info bitmap is a subset of each one of them
 */
static bool is_soo_rt_selected_pi_subset_of_all_rts_with_soo_using_soo_nhg_pi(
	struct bgp_per_src_nhg_hash_entry *bgp_per_src_nhg_entry)
{
	bool is_subset_of_all_routes = true;

	/* Walk only the 'routes with SoO' that use SoO NHG, not ALL 'route with
	 * SoO'
	 */
	hash_iterate(bgp_per_src_nhg_entry->route_with_soo_table,
		     (void (*)(struct hash_bucket *, void *))bgp_per_src_nhg_subset_check_cb,
		     &is_subset_of_all_routes);

	/* 'SoO route' pi bitmap is subset of ALL 'route with SoO' */
	return is_subset_of_all_routes;
}

/* Utils */
static bool bgp_is_soo_route(struct bgp_dest *dest, struct bgp_path_info *pi, struct in_addr *ip)
{
	struct prefix to;
	struct prefix *p = &dest->rn->p;

	memset(ip, 0, sizeof(*ip));
	if (!route_get_ip_from_soo_attr(pi, ip))
		return false;

	if (p) {
		if (p->family == AF_INET) {
			inaddrv42prefix(ip, 32, &to);
			if (prefix_same(&to, p))
				return true;
		} else if (p->family == AF_INET6) {
			struct in_addr ipv4;
			if (IS_MAPPED_IPV6(&p->u.prefix6)) {
				ipv4_mapped_ipv6_to_ipv4(&p->u.prefix6, &ipv4);
				if (IPV4_ADDR_SAME(&ipv4, ip))
					return true;
			}
		}
	}

	return false;
}

bool bgp_check_is_soo_route(struct bgp *bgp, struct bgp_dest *dest, struct bgp_path_info *pi)
{
	struct in_addr ip;

	if (route_has_soo_attr(pi) && bgp_is_soo_route(dest, pi, &ip))
		return true;
	else
		return false;
}

static char *print_bitfield(const bitfield_t *bf, char *out)
{
	if (!bf || !out)
		return NULL;

	unsigned int bit = 0;
	int offset = 0;

	bf_for_each_set_bit((*bf), bit, BGP_PEER_INIT_BITMAP_SIZE)
	{
		if (bit != 0)
			offset += sprintf(out + offset, "%u ", bit);
	}

	if (offset == 0)
		sprintf(out, "(empty)");

	return out;
}

char *inaddr_afi_to_str(const struct in_addr *id, char *buf, int size, afi_t afi)
{
	memset(buf, 0, size);
	if (afi == AFI_IP) {
		inet_ntop(AF_INET, id, buf, size);
	} else if (afi == AFI_IP6) {
		struct in6_addr v6addr;
		ipv4_to_ipv4_mapped_ipv6(&v6addr, *id);
		inet_ntop(AF_INET6, &v6addr, buf, size);
	}

	return buf;
}

static char *ipaddr_afi_to_str(const struct in_addr *id, char *buf, int size, afi_t afi)
{
	memset(buf, 0, size);
	if (afi == AFI_IP) {
		inet_ntop(AF_INET, id, buf, size);
	} else if (afi == AFI_IP6) {
		struct in6_addr v6addr;
		char addrbuf[BUFSIZ];
		struct prefix p = { 0 };

		ipv4_to_ipv4_mapped_ipv6(&v6addr, *id);
		inet_ntop(AF_INET6, &v6addr, addrbuf, BUFSIZ);
		in6addr2hostprefix(&v6addr, &p);
		prefix2str(&p, buf, size);
	}

	return buf;
}

bool is_nhg_per_origin_configured(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;
	bool nhg_per_origin = false;
	FOREACH_AFI_SAFI (afi, safi) {
		if (CHECK_FLAG(bgp->per_src_nhg_flags[afi][safi], BGP_FLAG_NHG_PER_ORIGIN)) {
			nhg_per_origin = true;
			break;
		}
	}

	return nhg_per_origin;
}

bool is_adv_origin_configured(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;
	bool adv_origin = false;
	FOREACH_AFI_SAFI (afi, safi) {
		if (CHECK_FLAG(bgp->per_src_nhg_flags[afi][safi], BGP_FLAG_ADVERTISE_ORIGIN)) {
			adv_origin = true;
			break;
		}
	}

	return adv_origin;
}

bool is_path_using_soo_nhg(const struct prefix *p, struct bgp_path_info *path, uint32_t *soo_nhg,
			   struct in_addr *soo)
{
	bool using_soo_nhg = false;
	struct bgp_dest *dest = path->net;
	struct bgp_table *table = NULL;
	afi_t afi;
	safi_t safi;

	if (!dest)
		return false;

	table = bgp_dest_table(dest);
	if (!table)
		return false;

	if (table->afi == AFI_L2VPN && table->safi == SAFI_EVPN)
		return false;

	afi = table->afi;
	safi = table->safi;

	if (is_nhg_per_origin_configured(path->peer->bgp) && route_has_soo_attr(path)) {
		struct in_addr in;
		bool is_soo_route = bgp_is_soo_route(path->net, path, &in);
		struct bgp_per_src_nhg_hash_entry *nhe = NULL;
		struct ipaddr ip;

		memset(&ip, 0, sizeof(struct ipaddr));
		SET_IPADDR_V4(&ip);
		memcpy(&ip.ipaddr_v4, &in, sizeof(ip.ipaddr_v4));
		nhe = bgp_per_src_nhg_find(path->peer->bgp, &ip, afi, safi);

		if (nhe) {
			if (is_soo_route) {
				if (bf_test_index(nhe->bgp_soo_route_installed_pi_bitmap,
						  path->peer->bit_index)) {
					using_soo_nhg = true;
					*soo_nhg = nhe->nhg_id;
					memcpy(soo, &in, sizeof(struct in_addr));
				}
			} else {
				struct bgp_dest_soo_hash_entry *dest_he;
				dest_he = bgp_dest_soo_find(nhe, p);
				if (dest_he && CHECK_FLAG(dest_he->flags, DEST_USING_SOO_NHGID)) {
					using_soo_nhg = true;
					*soo_nhg = nhe->nhg_id;
					memcpy(soo, &in, sizeof(struct in_addr));
				}
			}
		}
	}

	return using_soo_nhg;
}

static void bgp_per_src_nhg_del(struct bgp_per_src_nhg_hash_entry *nhe)
{
	struct bgp_per_src_nhg_hash_entry *tmp_nhe;
	struct bgp *bgp = nhe->bgp;
	afi_t afi = nhe->afi;
	safi_t safi = nhe->safi;

	bgp_nhg_id_free(PER_SRC_NHG, nhe->nhg_id);
	bgp_stop_soo_timer(nhe->bgp, nhe);

	bgp_nhg_nexthop_cache_reset(&nhe->nhg_nexthop_cache_table);

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
		char buf[INET6_ADDRSTRLEN];
		ipaddr2str(&nhe->ip, buf, sizeof(buf));
		zlog_debug("bgp vrf %s per src nhg %s %s del", nhe->bgp->name_pretty, buf,
			   get_afi_safi_str(nhe->afi, nhe->safi, false));
	}

	bgp_dest_soo_finish(nhe);
	tmp_nhe = hash_release(nhe->bgp->per_src_nhg_table[afi][safi], nhe);
	bgp_per_src_nhe_free(tmp_nhe);
	if (!bgp->per_src_nhg_table[afi][safi]->count &&
	    CHECK_FLAG(bgp->per_src_nhg_flags[afi][safi], BGP_FLAG_CONFIG_DEL_PENDING)) {
		UNSET_FLAG(bgp->per_src_nhg_flags[afi][safi], BGP_FLAG_CONFIG_DEL_PENDING);
		UNSET_FLAG(bgp->per_src_nhg_flags[afi][safi], BGP_FLAG_NHG_PER_ORIGIN);
		bgp_clear(NULL, bgp, afi, safi, clear_all, BGP_CLEAR_SOFT_IN, NULL);
	}
}

/* Install 'Route with SOO' to Zebra */
static void bgp_rt_with_soo_zebra_route_install(struct bgp_dest_soo_hash_entry *bgp_dest_soo_entry,
						struct bgp_per_src_nhg_hash_entry *nhe)
{
	struct bgp_path_info *pi;
	struct bgp_dest *dest = bgp_dest_soo_entry->dest;
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED) &&
		    (pi->type == ZEBRA_ROUTE_BGP && pi->sub_type == BGP_ROUTE_NORMAL) &&
		    !BGP_PATH_HOLDDOWN(pi))
			bgp_zebra_route_install(dest, pi, nhe->bgp, true, NULL, false);
	}
}

/* Install 'SOO Route' to Zebra */
static void bgp_soo_zebra_route_install(struct bgp_per_src_nhg_hash_entry *nhe,
					struct bgp_dest *dest)
{
	struct bgp_path_info *pi;
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED) &&
		    (pi->type == ZEBRA_ROUTE_BGP && pi->sub_type == BGP_ROUTE_NORMAL))
			bgp_zebra_route_install(dest, pi, nhe->bgp, true, NULL, false);
	}

	return;
}

/* Send ZEBRA_NHG_ADD to Zebra */
static void bgp_per_src_nhg_add_send(struct bgp_per_src_nhg_hash_entry *nhe)
{
	uint32_t nhg_id = nhe->nhg_id;
	struct zapi_nexthop *api_nh;
	struct zapi_nhg api_nhg = {};
	struct bgp_nhg_nexthop_cache_head *tree;
	struct bgp_nhg_nexthop_cache *bnc_iter;
	char buf[INET6_ADDRSTRLEN];

	/* Skip installation of L3-NHG if host routes used */
	if (!nhg_id)
		return;

	ipaddr2str(&nhe->ip, buf, sizeof(buf));

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg %s %s id %d add to zebra", nhe->bgp->name_pretty,
			   buf, get_afi_safi_str(nhe->afi, nhe->safi, false), nhe->nhg_id);

	api_nhg.id = nhg_id;
	SET_FLAG(api_nhg.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	tree = &nhe->nhg_nexthop_cache_table;

	frr_each (bgp_nhg_nexthop_cache, tree, bnc_iter) {
		if (!CHECK_FLAG(bnc_iter->nh.flags, BGP_NEXTHOP_VALID))
			continue;

		/* Don't overrun the zapi buffer. */
		if (api_nhg.nexthop_num == MULTIPATH_NUM)
			break;

		/* convert to zapi format */
		api_nh = &api_nhg.nexthops[api_nhg.nexthop_num];
		zapi_nexthop_from_nexthop(api_nh, &bnc_iter->nh);
		api_nh->weight = bnc_iter->nh_weight;
		++api_nhg.nexthop_num;
	}

	if (!api_nhg.nexthop_num)
		return;

	zclient_nhg_send(zclient, ZEBRA_NHG_ADD, &api_nhg);
	SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID);
	UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING);
	frrtrace(1, frr_bgp, per_src_nhg_add_send, nhe);
	assert(bf_is_inited(nhe->bgp_soo_route_selected_pi_bitmap));
	if (bf_is_inited(nhe->bgp_soo_route_installed_pi_bitmap))
		bf_free(nhe->bgp_soo_route_installed_pi_bitmap);
	nhe->bgp_soo_route_installed_pi_bitmap = bf_copy(nhe->bgp_soo_route_selected_pi_bitmap);
}

/* Send ZEBRA_NHG_DEL to Zebra */
static void bgp_per_src_nhg_del_send(struct bgp_per_src_nhg_hash_entry *nhe)
{
	struct zapi_nhg api_nhg = {};

	api_nhg.id = nhe->nhg_id;
	char buf[INET6_ADDRSTRLEN];

	/* Skip installation of L3-NHG if host routes used */
	if (!api_nhg.id)
		return;

	ipaddr2str(&nhe->ip, buf, sizeof(buf));
	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg %s %s id %d del to zebra", nhe->bgp->name_pretty,
			   buf, get_afi_safi_str(nhe->afi, nhe->safi, false), nhe->nhg_id);

	zclient_nhg_send(zclient, ZEBRA_NHG_DEL, &api_nhg);
	UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID);
	UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING);
	frrtrace(1, frr_bgp, per_src_nhg_del_send, nhe);
	assert(bf_is_inited(nhe->bgp_soo_route_selected_pi_bitmap));
	if (bf_is_inited(nhe->bgp_soo_route_installed_pi_bitmap))
		bf_free(nhe->bgp_soo_route_installed_pi_bitmap);
	nhe->bgp_soo_route_installed_pi_bitmap = bf_copy(nhe->bgp_soo_route_selected_pi_bitmap);
}

static void bgp_per_src_nhg_move_to_soo_nhid_cb(struct hash_bucket *bucket, void *ctx)
{
	struct bgp_dest_soo_hash_entry *route_with_soo_entry =
		(struct bgp_dest_soo_hash_entry *)bucket->data;

	if (route_with_soo_entry) {
		/* only move those which are not using soo nhid yet */
		if (!CHECK_FLAG(route_with_soo_entry->flags, DEST_USING_SOO_NHGID) &&
		    is_soo_rt_installed_pi_subset_of_rt_with_soo_pi(route_with_soo_entry))
			bgp_rt_with_soo_zebra_route_install(route_with_soo_entry,
							    route_with_soo_entry->nhe);
	}
}

static void bgp_per_src_nhg_move_to_zebra_nhid_cb(struct hash_bucket *bucket, void *ctx)
{
	struct bgp_dest_soo_hash_entry *route_with_soo_entry =
		(struct bgp_dest_soo_hash_entry *)bucket->data;

	if (route_with_soo_entry) {
		/* only move those which are using soo nhid yet */
		if (CHECK_FLAG(route_with_soo_entry->flags, DEST_USING_SOO_NHGID))
			bgp_rt_with_soo_zebra_route_install(route_with_soo_entry,
							    route_with_soo_entry->nhe);
	}
}

/* SoO timer expiry */
static void bgp_per_src_nhg_timer_slot_run(void *item)
{
	struct bgp_per_src_nhg_hash_entry *nhe = item;
	struct bgp_dest *dest;

	/* If SOO selected NHs match installed SOO NHG AND
	 * all routes w/ SOO point to SOO NHG done
	 *
	 * 	# Case for moving routes from zebra NHG to SOO NHG
	 * If SOO selected NHs match installed SOO NHG
	 *   -- Evaluate all routes w/ SOO and update those were the SOO NHG's
	 * NHs are a strict subset of route's selected NHs to SOO NHG; other
	 * routes remain on zebra NHG
	 *    -- done
	 *
	 * 	# Case for expanding the SOO NHG
	 *  If the SOO's new selected NHs are still a strict subset of all the
	 *  routes that already point to SOO_NHG expand the SOO_NHG done
	 */

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg soo %pIA %s timer slot run",
			   nhe->bgp->name_pretty, &nhe->ip,
			   get_afi_safi_str(nhe->afi, nhe->safi, false));

	/* all routes with soo converged to soo route */
	if (is_soo_rt_selected_pi_subset_of_all_rts_with_soo_using_soo_nhg_pi(nhe)) {
		/* program the running ecmp and do NHG replace */
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug("bgp vrf %s per src nhg soo route %pIA %s pi is subset of "
				   "all route with soo using soo nhg "
				   "remove soo entry from timer wheel",
				   nhe->bgp->name_pretty, &nhe->ip,
				   get_afi_safi_str(nhe->afi, nhe->safi, false));

		frrtrace(2, frr_bgp, per_src_nhg_soo_timer_slot_run, nhe, 1);

		if (nhe->refcnt)
			if (CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING))
				bgp_per_src_nhg_add_send(nhe);

		/* remove the timer from the timer wheel since processing is
		 * done */
		bgp_stop_soo_timer(nhe->bgp, nhe);
	} else {
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug("bgp vrf %s per src nhg soo route %pIA %s not all route "
				   "with soo converged",
				   nhe->bgp->name_pretty, &nhe->ip,
				   get_afi_safi_str(nhe->afi, nhe->safi, false));
		return;
	}

	dest = nhe->dest;
	/* 'SOO route' dest */
	if (!CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL)) {
		bgp_soo_zebra_route_install(nhe, dest);
		SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL);
	}

	/* Check for expansion case and then install the soo route with soo
	 * nhid if it satisfies
	 */

	/* Walk all the 'routes with SoO' and move from zebra nhid to soo nhid
	 */
	hash_iterate(nhe->route_with_soo_table,
		     (void (*)(struct hash_bucket *, void *))bgp_per_src_nhg_move_to_soo_nhid_cb,
		     NULL);
}

/* Add to SOO NHG nexthop cache */
static void bgp_per_src_nhg_nc_add(afi_t afi, struct bgp_per_src_nhg_hash_entry *nhe,
				   struct bgp_path_info *pi)
{
	ifindex_t ifindex = 0;
	struct prefix p = { 0 };
	struct bgp_nhg_nexthop_cache *bnc;
	uint32_t nh_weight;
	bool do_wt_ecmp = false;

	if (!pi->attr) {
		zlog_err("pi attr is NULL for bgp(%s) peer %p afi:%d add bnc",
			 nhe->bgp->name_pretty, pi->peer, afi);
		return;
	}

	/* Validation for the ipv4 mapped ipv6 nexthop. */
	if (IS_MAPPED_IPV6(&pi->attr->mp_nexthop_global)) {
		afi = AFI_IP;
	} else {
		afi = BGP_ATTR_MP_NEXTHOP_LEN_IP6(pi->attr) ? AFI_IP6 : AFI_IP;
	}

	if (make_prefix(afi, pi, &p) < 0)
		return;

	/*
	 * If it's a V6 nexthop, path is learnt from a v6 LL peer,
	 * and if the NH prefix matches peer's LL address then
	 * set the ifindex to peer's interface index so that
	 * correct nexthop can be found in nexthop tree.
	 *
	 * NH could be set to different v6 LL address (compared to
	 * peer's LL) using route-map. In such a scenario, do not set
	 * the ifindex.
	 */
	if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL(&pi->peer->connection->su.sin6.sin6_addr) &&
	    (memcmp(&pi->peer->connection->su.sin6.sin6_addr, &p.u.prefix6,
		    sizeof(struct in6_addr)) == 0))
		ifindex = pi->peer->connection->su.sin6.sin6_scope_id;

	nh_weight = 0;
	/* Determine if we're doing weighted ECMP or not */
	do_wt_ecmp = bgp_path_info_mpath_chkwtd(nhe->bgp, pi);
	if (do_wt_ecmp) {
		SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_DO_WECMP);
	} else if (CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_DO_WECMP)) {
		do_wt_ecmp = true;
	}

	bnc = bnc_nhg_find(&nhe->nhg_nexthop_cache_table, &p, ifindex);
	if (!bnc) {
		int nh_othervrf = 0;
		struct bgp *bgp_orig;
		bool nh_updated = false;
		bool is_parent_evpn;
		struct zapi_nexthop api_nh = { 0 };

		bnc = bnc_nhg_new(&nhe->nhg_nexthop_cache_table, &p, ifindex);
		BGP_ORIGINAL_UPDATE(bgp_orig, pi, nhe->bgp);
		is_parent_evpn = is_route_parent_evpn(pi);

		if (afi == AFI_IP) {
			(void)update_ipv4nh_for_route_install(nh_othervrf, bgp_orig,
							      &pi->attr->nexthop, pi->attr,
							      is_parent_evpn, &api_nh);
			bnc->nh.gate.ipv4 = api_nh.gate.ipv4;
		} else if (afi == AFI_IP6) {
			ifindex_t ifindex = IFINDEX_INTERNAL;
			struct in6_addr *nexthop;
			struct bgp_path_info *select = NULL;

			nexthop = bgp_path_info_to_ipv6_nexthop(pi, &ifindex);

			if (!nexthop) {
				(void)update_ipv4nh_for_route_install(nh_othervrf, bgp_orig,
								      &pi->attr->nexthop, pi->attr,
								      is_parent_evpn, &api_nh);
				bnc->nh.gate.ipv4 = api_nh.gate.ipv4;
			} else {
				if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
					select = pi;

				nh_updated = update_ipv6nh_for_route_install(nh_othervrf, bgp_orig,
									     nexthop, ifindex, pi,
									     select, is_parent_evpn,
									     &api_nh);
				if (!nh_updated) {
					zlog_err("Unable to get ipv6 nexthop for bnc nhg %pFX(%d)(%s) peer %p afi:%d",
						 &bnc->prefix, bnc->ifindex, nhe->bgp->name_pretty,
						 pi->peer, afi);
					bnc_nhg_free(bnc);
					return;
				}
				bnc->nh.gate.ipv6 = api_nh.gate.ipv6;
			}
		}
		bnc->nh.ifindex = api_nh.ifindex;
		bnc->nh.type = api_nh.type;
		bnc->nh.flags = api_nh.flags;
		bnc->nh.vrf_id = bgp_orig->vrf_id;
		SET_FLAG(bnc->nh.flags, NEXTHOP_FLAG_RECURSIVE);

		if (do_wt_ecmp && pi->attr)
			bgp_zebra_use_nhop_weighted(nhe->bgp, pi->attr, &nh_weight);

		bnc->nh_weight = nh_weight;
		SET_FLAG(bnc->nh.flags, BGP_NEXTHOP_VALID);
		SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING);
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug("Allocated bnc nhg %pFX(%d)(%s) peer %p refcnt:%d wei::%d attr wei:%d afi:%d ecmp:%d",
				   &bnc->prefix, bnc->ifindex, nhe->bgp->name_pretty, pi->peer,
				   nhe->refcnt, bnc->nh_weight, pi->attr->link_bw, afi, do_wt_ecmp);
	} else {
		if (do_wt_ecmp) {
			bgp_zebra_use_nhop_weighted(nhe->bgp, pi->attr, &nh_weight);
			if (bnc->nh_weight != nh_weight) {
				bnc->nh_weight = nh_weight;
				SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING);
			}
		}
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug("Found existing bnc nhg %pFX(%d)(%s) peer %p refcnt:%d wei:%d attr wei:%d ecmp:%d",
				   &bnc->prefix, bnc->ifindex, nhe->bgp->name_pretty, pi->peer,
				   nhe->refcnt, bnc->nh_weight, pi->attr->link_bw, do_wt_ecmp);
	}

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("Linked pi to bnc nhg %pFX(%d)(%s) peer %p", &bnc->prefix, bnc->ifindex,
			   nhe->bgp->name_pretty, pi->peer);
}

/* Delete from SOO NHG nexthop cache */
static void bgp_per_src_nhg_nc_del(afi_t afi, struct bgp_per_src_nhg_hash_entry *nhe,
				   struct bgp_path_info *pi)
{
	ifindex_t ifindex = 0;
	struct prefix p = { 0 };
	struct bgp_nhg_nexthop_cache *bnc;

	if (!pi->attr) {
		zlog_err("pi attr is NULL for bgp(%s) peer %p afi:%d del bnc",
			 nhe->bgp->name_pretty, pi->peer, afi);
		return;
	}

	/* Validation for the ipv4 mapped ipv6 nexthop. */
	if (IS_MAPPED_IPV6(&pi->attr->mp_nexthop_global)) {
		afi = AFI_IP;
	} else {
		afi = BGP_ATTR_MP_NEXTHOP_LEN_IP6(pi->attr) ? AFI_IP6 : AFI_IP;
	}

	if (make_prefix(afi, pi, &p) < 0)
		return;

	if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6))
		ifindex = pi->peer->connection->su.sin6.sin6_scope_id;

	bnc = bnc_nhg_find(&nhe->nhg_nexthop_cache_table, &p, ifindex);
	if (!bnc) {
		zlog_debug("pi bnc nhg %pFX(%d)(%s) peer %p not found", &p, ifindex,
			   nhe->bgp->name_pretty, pi->peer);
		return;
	}

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("Unlink and free pi bnc nhg %pFX(%d)(%s) peer %p", &bnc->prefix,
			   bnc->ifindex, nhe->bgp->name_pretty, pi->peer);
	UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_DO_WECMP);
	SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING);
	bnc_nhg_free(bnc);
}

static struct bgp_dest_soo_hash_entry *bgp_dest_soo_add(struct bgp_per_src_nhg_hash_entry *nhe,
							struct bgp_dest *dest)
{
	struct bgp_dest_soo_hash_entry tmp_he;
	struct bgp_dest_soo_hash_entry *dest_he = NULL;
	char buf[INET6_ADDRSTRLEN];
	char pfxprint[PREFIX2STR_BUFFER];
	struct prefix *p = &dest->rn->p;

	prefix2str(p, pfxprint, sizeof(pfxprint));

	memset(&tmp_he, 0, sizeof(tmp_he));
	prefix_copy(&tmp_he.p, p);
	dest_he = hash_get(nhe->route_with_soo_table, &tmp_he, bgp_dest_soo_alloc);
	dest_he->nhe = nhe;
	dest_he->dest = dest;

	bf_init(dest_he->bgp_pi_bitmap, BGP_PEER_INIT_BITMAP_SIZE);
	bf_assign_zero_index(dest_he->bgp_pi_bitmap);

	ipaddr2str(&nhe->ip, buf, sizeof(buf));

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg %s %s dest soo %s add", nhe->bgp->name_pretty,
			   buf, get_afi_safi_str(nhe->afi, nhe->safi, false), pfxprint);
	return dest_he;
}

static void bgp_dest_soo_del(struct bgp_dest_soo_hash_entry *dest_he,
			     struct bgp_per_src_nhg_hash_entry *nhe)
{
	struct bgp_dest_soo_hash_entry *tmp_he;

	bgp_dest_soo_flush_entry(dest_he);
	tmp_he = hash_release(nhe->route_with_soo_table, dest_he);
	bgp_dest_soo_free(tmp_he);

	/* check if nhe del pending and process */
	if (CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_DEL_PENDING) &&
	    !CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID) &&
	    !CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED) &&
	    !nhe->route_with_soo_use_nhid_cnt) {
		bgp_per_src_nhg_del_send(nhe);
		bgp_per_src_nhg_del(nhe);
	}
}

static void bgp_process_dest_soo_del(struct bgp_dest_soo_hash_entry *dest_he)
{
	struct bgp_per_src_nhg_hash_entry *nhe = dest_he->nhe;

	if (CHECK_FLAG(dest_he->flags, DEST_USING_SOO_NHGID)) {
		/* wait for route with soo to move to zebra nhid */
		SET_FLAG(dest_he->flags, DEST_SOO_DEL_PENDING);
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
			char buf[INET6_ADDRSTRLEN];
			char pfxprint[PREFIX2STR_BUFFER];
			ipaddr2str(&nhe->ip, buf, sizeof(buf));
			prefix2str(&dest_he->p, pfxprint, sizeof(pfxprint));
			zlog_debug("bgp vrf %s per src nhg %s %s dest soo %s del pending",
				   nhe->bgp->name_pretty, buf,
				   get_afi_safi_str(nhe->afi, nhe->safi, false), pfxprint);
		}
	} else {
		bgp_dest_soo_del(dest_he, nhe);
	}
}

static struct bgp_per_src_nhg_hash_entry *bgp_per_src_nhg_add(struct bgp *bgp, struct ipaddr *ip,
							      afi_t afi, safi_t safi)
{
	struct bgp_per_src_nhg_hash_entry tmp_nhe;
	struct bgp_per_src_nhg_hash_entry *nhe = NULL;

	memset(&tmp_nhe, 0, sizeof(tmp_nhe));
	memcpy(&tmp_nhe.ip, ip, sizeof(struct ipaddr));

	nhe = hash_get(bgp->per_src_nhg_table[afi][safi], &tmp_nhe, bgp_per_src_nhg_alloc);

	nhe->bgp = bgp;
	nhe->afi = afi;
	nhe->safi = safi;

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg soo entry create: %pIA %s", bgp->name_pretty,
			   &nhe->ip, get_afi_safi_str(nhe->afi, nhe->safi, false));

	bgp_dest_soo_init(nhe);
	bf_init(nhe->bgp_soo_route_selected_pi_bitmap, BGP_PEER_INIT_BITMAP_SIZE);
	bf_assign_zero_index(nhe->bgp_soo_route_selected_pi_bitmap);
	bf_init(nhe->bgp_soo_route_installed_pi_bitmap, BGP_PEER_INIT_BITMAP_SIZE);
	bf_assign_zero_index(nhe->bgp_soo_route_installed_pi_bitmap);

	bgp_nhg_nexthop_cache_init(&nhe->nhg_nexthop_cache_table);

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
		char buf[INET6_ADDRSTRLEN];
		ipaddr2str(ip, buf, sizeof(buf));
		zlog_debug("bgp vrf %s per src nhg %s %s add", bgp->name_pretty, buf,
			   get_afi_safi_str(nhe->afi, nhe->safi, false));
	}

	return nhe;
}

static void bgp_per_src_nhg_delete(struct bgp_per_src_nhg_hash_entry *nhe)
{
	struct bgp_dest *dest;

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg soo %pIA %s nhg delete cnt:%d and flags %d",
			   nhe->bgp->name_pretty, &nhe->ip,
			   get_afi_safi_str(nhe->afi, nhe->safi, false),
			   nhe->route_with_soo_use_nhid_cnt, nhe->flags);
	/* Can't delete soo NHID till all routes with soo and soo route is moved
	 * to zebra nhid
	 */
	if (!nhe->route_with_soo_use_nhid_cnt &&
	    !CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED)) {
		if (CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING))
			bgp_per_src_nhg_del_send(nhe);
		bgp_per_src_nhg_del(nhe);
	} else {
		UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID);
		SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_DEL_PENDING);

		if (CHECK_FLAG(nhe->bgp->per_src_nhg_flags[nhe->afi][nhe->safi],
			       BGP_FLAG_CONFIG_DEL_PENDING)) {
			/* Walk all the 'routes with SoO' and move from zebra
			 * nhid to soo nhid */
			hash_iterate(nhe->route_with_soo_table,
				     (void (*)(struct hash_bucket *,
					       void *))bgp_per_src_nhg_move_to_zebra_nhid_cb,
				     NULL);
			/* 'SOO route' dest */
			dest = nhe->dest;
			if (dest && CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL)) {
				bgp_soo_zebra_route_install(nhe, dest);
				UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL);
			}
		}
		nhe->dest = NULL;
	}
	return;
}

/* Check and see if SOO NHG can be replaced with new ECMP, this happens when the
 * new selected ECMP of SOO route is a subset of installed ECMP of SOO route
 * Example: Remote link failure scenarios
 */
void bgp_per_src_nhg_upd_msg_check(struct bgp *bgp, afi_t afi, safi_t safi, struct bgp_dest *dest)
{
	struct ipaddr ip;
	struct bgp_per_src_nhg_hash_entry *nhe;
	struct bgp_table *table = NULL;
	struct prefix *p = &dest->rn->p;

	table = bgp_dest_table(dest);
	if (table &&
	    ((table->afi == AFI_L2VPN && table->safi == SAFI_EVPN) ||
	     !CHECK_FLAG(bgp->per_src_nhg_flags[table->afi][table->safi], BGP_FLAG_NHG_PER_ORIGIN)))
		return;

	memset(&ip, 0, sizeof(ip));
	SET_IPADDR_V4(&ip);

	if (p) {
		if (p->family == AF_INET) {
			memcpy(&ip.ipaddr_v4, &dest->rn->p.u.prefix4, sizeof(dest->rn->p.u.prefix4));
		} else if (p->family == AF_INET6) {
			struct in_addr ipv4;
			if (IS_MAPPED_IPV6(&p->u.prefix6)) {
				ipv4_mapped_ipv6_to_ipv4(&p->u.prefix6, &ipv4);
				memcpy(&ip.ipaddr_v4, &ipv4, sizeof(ipv4));
			}
		}
	}

	nhe = bgp_per_src_nhg_find(bgp, &ip, afi, safi);
	/*  bgp_soo_route_installed_pi_bitmap -> what is installed in the kernel
	 *	(old/existing)
	 *	bgp_soo_route_selected_pi_bitmap 		 -> what is
	 *received from BGP update (new)
	 *
	 *	We can have 4 cases between bgp_soo_route_selected_pi_bitmap and
	 *	bgp_soo_route_installed_pi_bitmap
	 *	Case 1: bgp_soo_route_selected_pi_bitmap and
	 *	bgp_soo_route_installed_pi_bitmap are 'DISJOINT'
	 *
	 *	Case 2: bgp_soo_route_selected_pi_bitmap and
	 *	bgp_soo_route_installed_pi_bitmap are 'OVERLAPPING'
	 *
	 *	Case 3: bgp_soo_route_selected_pi_bitmap is 'SUBSET' of
	 *	bgp_soo_route_installed_pi_bitmap
	 *		Case a:
	 *			ECMP Case (3).(a).(i): ECMP Shrink
	 *				Example 1: old = NH1 NH2 NH3
	 *							new = NH1 NH3
	 *		Case b: W-ECMP Case
	 *			(3).(b).(i): Same ECMP but weights increase or
	 *decrease Example 1: old = NH1,255/NH2,85/NH3,127 new =
	 *NH1,255/NH2,255/NH3,255 Example 2: old = NH1,255/NH2,255/NH3,255 new =
	 *NH1,255/NH2,85/NH3,127 case (3).(b).(ii):ECMP Shrink with weights
	 *increase or decrease Example 1: old = NH1,255/NH2,255/NH3,166 new =
	 *NH1,255/NH3,85 Example 2: old = NH1,255/NH2,255/NH3,166 new =
	 *NH1,255/NH3,255
	 *
	 *	Case 4: bgp_soo_route_selected_pi_bitmap is 'SUPERSET' of
	 *	bgp_soo_route_installed_pi_bitmap
	 */
	if (nhe && nhe->refcnt && CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING)) {
		/* running is subset of installed - shrink case - immediate nhg
		 * replace
		 */
		if (bf_is_subset(&nhe->bgp_soo_route_selected_pi_bitmap,
				 &nhe->bgp_soo_route_installed_pi_bitmap)) {
			/* Case 3: Subset (shrink or link bandwidth change)
			 * NHG replace can be done immediately without waiting
			 * for any timer
			 */
			if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
				char buf1[BUFSIZ] = { 0 };
				char buf2[BUFSIZ] = { 0 };
				zlog_debug("bgp vrf %s per src nhg soo route upd: %pIA %s NHG replace"
					   "(shrink or link bandwidth change) selected pi %s, installed pi %s",
					   nhe->bgp->name_pretty, &nhe->ip,
					   get_afi_safi_str(nhe->afi, nhe->safi, false),
					   print_bitfield(&nhe->bgp_soo_route_selected_pi_bitmap,
							  buf1),
					   print_bitfield(&nhe->bgp_soo_route_installed_pi_bitmap,
							  buf2));
			}
			frrtrace(2, frr_bgp, per_src_nhg_soo_rt_dest_ecmp_check, nhe, 1);
			bgp_per_src_nhg_add_send(nhe);
		} else {
			/* Case 1: Disjoint
			 * Case 2: Overlap
			 * Case 4: Superset
			 * NHG replace will be evaluted after SOO timer expiry,
			 * start the timer if its not already running
			 */
			if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
				char buf1[BUFSIZ] = { 0 };
				char buf2[BUFSIZ] = { 0 };
				zlog_debug("bgp vrf %s per src nhg soo route upd: %pIA %s NHG start SOO timer"
					   "selected pi %s is not subset of installed pi %s",
					   nhe->bgp->name_pretty, &nhe->ip,
					   get_afi_safi_str(nhe->afi, nhe->safi, false),
					   print_bitfield(&nhe->bgp_soo_route_selected_pi_bitmap,
							  buf1),
					   print_bitfield(&nhe->bgp_soo_route_installed_pi_bitmap,
							  buf2));
			}
			frrtrace(2, frr_bgp, per_src_nhg_soo_rt_dest_ecmp_check, nhe, 2);
			/*
			 * case where installed path subset is disjoint/overlap/superset
			 * from selected path subset
			 */
			bgp_start_soo_timer(bgp, nhe);
		}
	}
}

/* NHG ID APIs*/
void bgp_process_route_transition_between_nhid(struct bgp *bgp, struct bgp_dest *dest,
					       struct bgp_path_info *pi, bool withdraw)
{
	struct in_addr in;
	struct bgp_dest_soo_hash_entry *dest_he;
	struct bgp_per_src_nhg_hash_entry *nhe;
	bool is_evpn = false;
	struct bgp_table *table = NULL;
	struct ipaddr ip;
	bool is_soo_route = false;

	memset(&ip, 0, sizeof(ip));

	table = bgp_dest_table(dest);
	if (!table)
		return;

	if (table->afi == AFI_L2VPN && table->safi == SAFI_EVPN)
		is_evpn = true;

	if (!CHECK_FLAG(bgp->per_src_nhg_flags[table->afi][table->safi], BGP_FLAG_NHG_PER_ORIGIN) ||
	    is_evpn)
		return;


	if (route_has_soo_attr(pi)) {
		is_soo_route = bgp_is_soo_route(dest, pi, &in);
		SET_IPADDR_V4(&ip);
		memcpy(&ip.ipaddr_v4, &in, sizeof(ip.ipaddr_v4));

		nhe = bgp_per_src_nhg_find(bgp, &ip, table->afi, table->safi);
		if (!nhe)
			return;

		if (is_soo_route) {
			if (withdraw || CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_DEL_PENDING))
				UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED);
			if (CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_DEL_PENDING) &&
			    !CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID) &&
			    !CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED) &&
			    !nhe->route_with_soo_use_nhid_cnt) {
				bgp_per_src_nhg_del_send(nhe);
				bgp_per_src_nhg_del(nhe);
			}
		} else {
			dest_he = bgp_dest_soo_find(nhe, &dest->rn->p);
			if (!dest_he) {
				if (CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_DEL_PENDING) &&
				    !CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID) &&
				    !CHECK_FLAG(nhe->flags,
						PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED) &&
				    !nhe->route_with_soo_use_nhid_cnt) {
					bgp_per_src_nhg_del_send(nhe);
					bgp_per_src_nhg_del(nhe);
				}
				return;
			}

			if (withdraw && CHECK_FLAG(dest_he->flags, DEST_USING_SOO_NHGID)) {
				nhe->route_with_soo_use_nhid_cnt--;
				UNSET_FLAG(dest_he->flags, DEST_USING_SOO_NHGID);
			}

			if (CHECK_FLAG(dest_he->flags, DEST_SOO_DEL_PENDING))
				bgp_dest_soo_del(dest_he, nhe);
		}
	}
}

bool bgp_per_src_nhg_use_nhgid(struct bgp *bgp, struct bgp_dest *dest, struct bgp_path_info *pi,
			       uint32_t *nhg_id)
{
	struct in_addr in;
	struct bgp_dest_soo_hash_entry *dest_he;
	struct bgp_per_src_nhg_hash_entry *nhe;
	bool is_evpn = false;
	struct bgp_table *table = NULL;
	struct ipaddr ip;
	bool is_soo_route = false;
	char buf[INET6_ADDRSTRLEN];

	memset(&ip, 0, sizeof(ip));

	table = bgp_dest_table(dest);
	if (!table)
		return false;

	if (table->afi == AFI_L2VPN && table->safi == SAFI_EVPN)
		is_evpn = true;

	if (!CHECK_FLAG(bgp->per_src_nhg_flags[table->afi][table->safi], BGP_FLAG_NHG_PER_ORIGIN) ||
	    is_evpn)
		return false;

	if (route_has_soo_attr(pi)) {
		is_soo_route = bgp_is_soo_route(dest, pi, &in);
		SET_IPADDR_V4(&ip);
		memcpy(&ip.ipaddr_v4, &in, sizeof(ip.ipaddr_v4));

		nhe = bgp_per_src_nhg_find(bgp, &ip, table->afi, table->safi);
		if (!nhe)
			return false;

		ipaddr2str(&nhe->ip, buf, sizeof(buf));
		if (is_soo_route) {
			if (CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID) ||
			    (CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_DEL_PENDING) &&
			     !CHECK_FLAG(bgp->per_src_nhg_flags[table->afi][table->safi],
					 BGP_FLAG_CONFIG_DEL_PENDING) &&
			     !CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_ATTR_DEL))) {
				SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED);
				*nhg_id = nhe->nhg_id;
				if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
					zlog_debug("bgp vrf %s per src nhg %s %s "
						   "add to soo nhid",
						   nhe->bgp->name_pretty, buf,
						   get_afi_safi_str(nhe->afi, nhe->safi, false));
				frrtrace(2, frr_bgp, per_src_nhg_soo_rt_use_nhgid, nhe, 1);
				return true;
			} else {
				if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
					zlog_debug("bgp vrf %s per src nhg %s %s "
						   "del from soo nhid",
						   nhe->bgp->name_pretty, buf,
						   get_afi_safi_str(nhe->afi, nhe->safi, false));
				frrtrace(2, frr_bgp, per_src_nhg_soo_rt_use_nhgid, nhe, 2);
				return false;
			}
		} else {
			dest_he = bgp_dest_soo_find(nhe, &dest->rn->p);
			char buf[INET6_ADDRSTRLEN];
			char pfxprint[PREFIX2STR_BUFFER];
			if (!dest_he)
				return false;

			prefix2str(&dest_he->p, pfxprint, sizeof(pfxprint));
			if ((!is_soo_rt_installed_pi_subset_of_rt_with_soo_pi(dest_he) &&
			     (CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID))) ||
			    (CHECK_FLAG(bgp->per_src_nhg_flags[table->afi][table->safi],
					BGP_FLAG_CONFIG_DEL_PENDING)) ||
			    CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_ATTR_DEL) ||
			    CHECK_FLAG(dest_he->flags, DEST_SOO_ROUTE_ATTR_DEL) ||
			    ((!CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_VALID)) &&
			     (!CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_CLEAR_ONLY)) &&
			     (!CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_DEL_PENDING)))) {
				if (CHECK_FLAG(dest_he->flags, DEST_USING_SOO_NHGID)) {
					nhe->route_with_soo_use_nhid_cnt--;
					UNSET_FLAG(dest_he->flags, DEST_USING_SOO_NHGID);
					if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
						zlog_debug("bgp vrf %s per src nhg %s %s dest soo %s "
							   "del from soo nhid use list",
							   nhe->bgp->name_pretty, buf,
							   get_afi_safi_str(nhe->afi, nhe->safi,
									    false),
							   pfxprint);
					frrtrace(3, frr_bgp, per_src_nhg_rt_with_soo_use_nhgid, nhe,
						 dest_he, 1);
				}
				return false;
			}

			if (!CHECK_FLAG(dest_he->flags, DEST_USING_SOO_NHGID)) {
				nhe->route_with_soo_use_nhid_cnt++;
				SET_FLAG(dest_he->flags, DEST_USING_SOO_NHGID);
				if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
					zlog_debug("bgp vrf %s per src nhg %s dest soo %s %s"
						   "add to soo nhid use list",
						   nhe->bgp->name_pretty, buf,
						   get_afi_safi_str(nhe->afi, nhe->safi, false),
						   pfxprint);
				}
				frrtrace(3, frr_bgp, per_src_nhg_rt_with_soo_use_nhgid, nhe,
					 dest_he, 2);
			}
			*nhg_id = nhe->nhg_id;
			return true;
		}
	}

	return false;
}

/* Process 'Route with SoO' */
static void bgp_process_route_with_soo_attr(struct bgp *bgp, afi_t afi, safi_t safi,
					    struct bgp_dest *dest, struct bgp_path_info *pi,
					    struct in_addr *ipaddr, bool is_add, bool soo_attr_del)
{
	struct bgp_dest_soo_hash_entry *dest_he;
	struct bgp_per_src_nhg_hash_entry *nhe;
	struct ipaddr ip;
	char buf[INET6_ADDRSTRLEN];
	char pfxprint[PREFIX2STR_BUFFER];

	prefix2str(&dest->rn->p, pfxprint, sizeof(pfxprint));

	memset(&ip, 0, sizeof(ip));
	SET_IPADDR_V4(&ip);
	memcpy(&ip.ipaddr_v4, ipaddr, sizeof(ip.ipaddr_v4));
	ipaddr2str(&ip, buf, sizeof(buf));

	nhe = bgp_per_src_nhg_find(bgp, &ip, afi, safi);
	if (!nhe) {
		if (is_add)
			nhe = bgp_per_src_nhg_add(bgp, &ip, afi, safi);
		else {
			if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
				zlog_debug("bgp vrf %s per src nhg not found %s %s dest soo %s del",
					   bgp->name_pretty, buf,
					   get_afi_safi_str(afi, safi, false), pfxprint);
			return;
		}
	} else {
		/*
		 * handle case where soo route was created due to arrival  route
		 * with soo arrive first.
		 */
		if (!is_add) {
			if (!nhe->refcnt &&
			    !CHECK_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED) &&
			    !nhe->route_with_soo_use_nhid_cnt)
				SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_DEL_PENDING);
		}
	}

	dest_he = bgp_dest_soo_find(nhe, &dest->rn->p);
	if (!dest_he) {
		if (is_add) {
			if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
				zlog_debug("bgp vrf %s per src nhg route with soo %s %s dest %s "
					   "peer %pSU idx %d add",
					   bgp->name_pretty, buf, get_afi_safi_str(afi, safi, false),
					   bgp_dest_get_prefix_str(dest), &pi->peer->connection->su,
					   pi->peer->bit_index);
			dest_he = bgp_dest_soo_add(nhe, dest);
		} else {
			if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
				zlog_debug("bgp vrf %s per src nhg %s %s dest soo %s not found for del oper",
					   bgp->name_pretty, buf,
					   get_afi_safi_str(afi, safi, false), pfxprint);
			return;
		}
	} else {
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
			zlog_debug("bgp vrf %s per src nhg route with soo %s %s dest %s "
				   "peer %pSU idx %d %s",
				   bgp->name_pretty, buf, get_afi_safi_str(afi, safi, false),
				   bgp_dest_get_prefix_str(dest), &pi->peer->connection->su,
				   pi->peer->bit_index, is_add ? "upd" : "del");
	}

	if (is_add) {
		if (!bf_test_index(dest_he->bgp_pi_bitmap, pi->peer->bit_index)) {
			bf_set_bit(dest_he->bgp_pi_bitmap, pi->peer->bit_index);
			dest_he->refcnt++;
			bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);
		}
	} else {
		if (bf_test_index(dest_he->bgp_pi_bitmap, pi->peer->bit_index)) {
			bf_release_index(dest_he->bgp_pi_bitmap, pi->peer->bit_index);
			dest_he->refcnt--;
			if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
				zlog_debug("bgp vrf %s per src nhg route with soo %s %s dest %s "
					   "peer %pSU idx %d %s refcnt:%d soo_attr_del:%d",
					   bgp->name_pretty, buf, get_afi_safi_str(afi, safi, false),
					   bgp_dest_get_prefix_str(dest), &pi->peer->connection->su,
					   pi->peer->bit_index, is_add ? "upd" : "del",
					   dest_he->refcnt, soo_attr_del);
			bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);

			if (soo_attr_del) {
				if (!dest_he->refcnt) {
					if (CHECK_FLAG(dest_he->flags, DEST_USING_SOO_NHGID)) {
						char buf[INET6_ADDRSTRLEN];
						char pfxprint[PREFIX2STR_BUFFER];
						ipaddr2str(&nhe->ip, buf, sizeof(buf));
						prefix2str(&dest_he->p, pfxprint, sizeof(pfxprint));
						nhe->route_with_soo_use_nhid_cnt--;
						UNSET_FLAG(dest_he->flags, DEST_USING_SOO_NHGID);
						SET_FLAG(dest_he->flags, DEST_SOO_ROUTE_ATTR_DEL);
						if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
							zlog_debug("bgp vrf %s per src nhg %s %s dest soo %s "
								   "del from soo nhid use list",
								   nhe->bgp->name_pretty, buf,
								   get_afi_safi_str(afi, safi,
										    false),
								   pfxprint);
						bgp_zebra_announce_actual(dest, pi, bgp);
					}
				}
			}

			if (!dest_he->refcnt)
				bgp_process_dest_soo_del(dest_he);
		}
	}
}

/* Process 'SoO Route' */
static void bgp_process_soo_route(struct bgp *bgp, afi_t afi, safi_t safi, struct bgp_dest *dest,
				  struct bgp_path_info *pi, struct in_addr *ipaddr, bool is_add,
				  bool soo_attr_del)
{
	struct ipaddr ip;
	struct bgp_per_src_nhg_hash_entry *nhe;

	/* find-create nh */
	memset(&ip, 0, sizeof(ip));
	SET_IPADDR_V4(&ip);
	memcpy(&ip.ipaddr_v4, ipaddr, sizeof(ip.ipaddr_v4));

	nhe = bgp_per_src_nhg_find(bgp, &ip, afi, safi);
	if (!nhe) {
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
			char buf[INET6_ADDRSTRLEN];
			ipaddr2str(&ip, buf, sizeof(buf));
			zlog_debug("bgp vrf %s per src nhg soo route soo %s %s dest %s "
				   "peer %pSU idx %d add",
				   bgp->name_pretty, buf, get_afi_safi_str(afi, safi, false),
				   bgp_dest_get_prefix_str(dest), &pi->peer->connection->su,
				   pi->peer->bit_index);
		}
		if (is_add) {
			nhe = bgp_per_src_nhg_add(bgp, &ip, afi, safi);
			nhe->dest = dest;
			/* Even though NHG is allocated here, it is programed
			 * in to zebra after soo timer expiry
			 */
			nhe->nhg_id = bgp_nhg_id_alloc(PER_SRC_NHG);
			bgp_start_soo_timer(bgp, nhe);
		} else
			return;
	} else {
		if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG)) {
			char buf[INET6_ADDRSTRLEN];
			ipaddr2str(&ip, buf, sizeof(buf));
			zlog_debug("bgp vrf %s per src nhg soo route soo %s %s dest %s "
				   "peer %pSU idx %d %s soo_attr_del:%d",
				   bgp->name_pretty, buf, get_afi_safi_str(afi, safi, false),
				   bgp_dest_get_prefix_str(dest), &pi->peer->connection->su,
				   pi->peer->bit_index, is_add ? "upd" : "del", soo_attr_del);
		}
		if (is_add) {
			/* Even though NHG is allocated here, it is
			   programed in to zebra after soo timer expiry */
			if (!nhe->nhg_id) {
				nhe->nhg_id = bgp_nhg_id_alloc(PER_SRC_NHG);
				bgp_start_soo_timer(bgp, nhe);
			}
			if (!nhe->dest)
				nhe->dest = dest;
		}
	}

	if (is_add) {
		if (!bf_test_index(nhe->bgp_soo_route_selected_pi_bitmap, pi->peer->bit_index)) {
			bf_set_bit(nhe->bgp_soo_route_selected_pi_bitmap, pi->peer->bit_index);
			nhe->refcnt++;
		}
		bgp_per_src_nhg_nc_add(afi, nhe, pi);
	} else {
		if (bf_test_index(nhe->bgp_soo_route_selected_pi_bitmap, pi->peer->bit_index)) {
			bf_release_index(nhe->bgp_soo_route_selected_pi_bitmap, pi->peer->bit_index);
			nhe->refcnt--;
			if (soo_attr_del && !nhe->refcnt) {
				UNSET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED);
				SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_ATTR_DEL);
			}
		}

		bgp_per_src_nhg_nc_del(afi, nhe, pi);
	}

	if (!nhe->refcnt) {
		bgp_per_src_nhg_delete(nhe);
		if (soo_attr_del)
			bgp_zebra_announce_actual(dest, pi, bgp);
	}
}

/* Check if route has soo attribute and process 'SOO route' or 'Route with SOO'
 */
void bgp_process_route_soo_attr(struct bgp *bgp, afi_t afi, safi_t safi, struct bgp_dest *dest,
				struct bgp_path_info *pi, bool is_add)
{
	struct in_addr ip;

	if (route_has_soo_attr(pi)) {
		if (bgp_is_soo_route(dest, pi, &ip))
			/* processing of 'soo route' */
			bgp_process_soo_route(bgp, afi, safi, dest, pi, &ip, is_add, false);
		else
			/* processing of 'route with soo' */
			bgp_process_route_with_soo_attr(bgp, afi, safi, dest, pi, &ip, is_add,
							false);
	}
}

/* Process route up on change of 'SOO attribute' */
void bgp_process_route_soo_attr_change(struct bgp *bgp, afi_t afi, safi_t safi,
				       struct bgp_dest *dest, struct bgp_path_info *pi,
				       struct attr *new_attr)
{
	struct in_addr ip;

	/* old select has the soo attr attached but new one doesn't */
	if (is_soo_attr(pi->attr) && !is_soo_attr(new_attr)) {
		/* when soo attr is removed from path, we need to immediately
		 * announce route to zebra, as we can delete nhg only when all
		 * routes are moved to zebra nhgid.
		 */
		if (bgp_is_soo_route(dest, pi, &ip)) {
			/* processing of 'soo route' */
			bgp_process_soo_route(bgp, afi, safi, dest, pi, &ip, false, true);

		} else {
			/* processing of 'route with soo' */
			bgp_process_route_with_soo_attr(bgp, afi, safi, dest, pi, &ip, false, true);
		}
	}
}

/* Process all multipaths of a bgp_dest for SOO attributes*/
void bgp_process_mpath_route_soo_attr(struct bgp *bgp, afi_t afi, safi_t safi, struct bgp_dest *dest,
				      struct bgp_path_info *mpinfo, bool is_add)
{
	for (; mpinfo; mpinfo = bgp_path_info_mpath_next(mpinfo)) {
		bgp_process_route_soo_attr(bgp, afi, safi, dest, mpinfo, is_add);
	}
}

static void bgp_per_src_nhg_peer_clear_route_cb(struct hash_bucket *bucket, void *ctx)
{
	struct bgp_path_info *pi;
	struct bgp_per_src_nhg_hash_entry *nhe = (struct bgp_per_src_nhg_hash_entry *)bucket->data;
	struct bgp_peer_clear_route_ctx *clear_ctx = (struct bgp_peer_clear_route_ctx *)ctx;
	struct peer *peer = clear_ctx->peer;
	struct bgp_table *table = clear_ctx->table;

	if (nhe && nhe->dest) {
		struct bgp_dest *dest = nhe->dest;
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if ((pi->peer == peer) &&
			    (pi->type == ZEBRA_ROUTE_BGP && pi->sub_type == BGP_ROUTE_NORMAL)) {
				SET_FLAG(nhe->flags, PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_CLEAR_ONLY);
				if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
					zlog_debug("bgp vrf %s per src nhg: peer clear processing soo route %pBD for peer %p",
						   peer->bgp->name_pretty, pi, peer);
				bgp_process(peer->bgp, dest, pi, table->afi, table->safi);
			}
		}
		frrtrace(2, frr_bgp, per_src_nhg_peer_clear_route, peer, nhe);
	}
}

void bgp_peer_clear_soo_routes(struct peer *peer, afi_t afi, safi_t safi, struct bgp_table *table)
{
	if (table && ((table->afi == AFI_L2VPN && table->safi == SAFI_EVPN) || !(peer->bgp) ||
		      !CHECK_FLAG(peer->bgp->per_src_nhg_flags[table->afi][table->safi],
				  BGP_FLAG_NHG_PER_ORIGIN)))
		return;

	if (BGP_DEBUG(per_src_nhg, PER_SRC_NHG))
		zlog_debug("bgp vrf %s per src nhg peer clear peer:%p", peer->bgp->name_pretty,
			   peer);

	if (peer->bgp->per_src_nhg_table[afi][safi]) {
		struct bgp_peer_clear_route_ctx ctx = {
			.peer = peer,
			.table = table,
		};
		hash_iterate(peer->bgp->per_src_nhg_table[afi][safi],
			     (void (*)(struct hash_bucket *,
				       void *))bgp_per_src_nhg_peer_clear_route_cb,
			     &ctx);
	}
}

/* Check and send if a new 'SOO route' up on router ID change*/
void bgp_per_src_nhg_handle_router_id_update(struct bgp *bgp, const struct in_addr *id)
{
	char soo[INET_ADDRSTRLEN + 6];
	struct ecommunity *ecomm_soo;
	char addrbuf[BUFSIZ];
	afi_t afi;
	safi_t safi;

	if (id->s_addr != INADDR_ANY) {
		snprintf(soo, sizeof(soo), "%s:%X", inet_ntoa(*id),
			 SOO_LOCAL_ADMINISTRATOR_VALUE_PER_SOURCE_NHG);
		ecomm_soo = ecommunity_str2com(soo, ECOMMUNITY_SITE_ORIGIN, 0);
		if (bgp->per_source_nhg_soo)
			ecommunity_free(&bgp->per_source_nhg_soo);
		bgp->per_source_nhg_soo = ecomm_soo;
		ecommunity_str(bgp->per_source_nhg_soo);

		FOREACH_AFI_SAFI (afi, safi) {
			if (CHECK_FLAG(bgp->per_src_nhg_flags[afi][safi],
				       BGP_FLAG_ADVERTISE_ORIGIN)) {
				bgp_static_set(NULL, bgp, true,
					       ipaddr_afi_to_str(&bgp->router_id, addrbuf, BUFSIZ,
								 afi),
					       NULL, NULL, afi, safi, NULL, 0,
					       BGP_INVALID_LABEL_INDEX, 0, NULL, NULL, NULL, NULL,
					       true, false);
				bgp_static_set(NULL, bgp, false,
					       ipaddr_afi_to_str(id, addrbuf, BUFSIZ, afi), NULL,
					       NULL, afi, safi, NULL, 0, BGP_INVALID_LABEL_INDEX, 0,
					       NULL, NULL, NULL, NULL, true, false);
			}
		}
	} else {
		if (bgp->per_source_nhg_soo) {
			ecommunity_free(&bgp->per_source_nhg_soo);
			bgp->per_source_nhg_soo = NULL;
		}

		FOREACH_AFI_SAFI (afi, safi) {
			if (CHECK_FLAG(bgp->per_src_nhg_flags[afi][safi],
				       BGP_FLAG_ADVERTISE_ORIGIN)) {
				bgp_static_set(NULL, bgp, true,
					       ipaddr_afi_to_str(&bgp->router_id, addrbuf, BUFSIZ,
								 afi),
					       NULL, NULL, afi, safi, NULL, 0,
					       BGP_INVALID_LABEL_INDEX, 0, NULL, NULL, NULL, NULL,
					       true, false);
			}
		}
	}
}
