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
