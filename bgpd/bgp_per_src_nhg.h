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

#include "typesafe.h"

#ifndef _BGP_PER_SRC_NHG_H
#define _BGP_PER_SRC_NHG_H

PREDECL_RBTREE_UNIQ(bgp_nhg_nexthop_cache);

struct bgp_nhg_nexthop_cache {
	ifindex_t ifindex;
	struct prefix prefix;
	struct nexthop nh;
	uint32_t nh_weight;
	/* RB-tree entry. */
	struct bgp_nhg_nexthop_cache_item entry;
	struct bgp_nhg_nexthop_cache_head *tree;
};

extern int bgp_nhg_nexthop_cache_compare(const struct bgp_nhg_nexthop_cache *a,
					 const struct bgp_nhg_nexthop_cache *b);

DECLARE_RBTREE_UNIQ(bgp_nhg_nexthop_cache, struct bgp_nhg_nexthop_cache, entry,
		    bgp_nhg_nexthop_cache_compare);

/*
 * Hashtables containing nhg entries is in `bgp_vrf`.
 */
struct bgp_dest_soo_hash_entry {
	struct bgp *bgp;
	struct bgp_per_src_nhg_hash_entry *nhe;

	struct prefix p;

	/* back pointer to dest */
	struct bgp_dest *dest;

	bitfield_t bgp_pi_bitmap;
	uint32_t refcnt;

	uint32_t flags;
#define DEST_USING_SOO_NHGID	(1 << 0)
#define DEST_SOO_DEL_PENDING	(1 << 1)
#define DEST_SOO_ROUTE_ATTR_DEL (1 << 2)
};

/*
 * Hashtables containing nhg entries is in `bgp_vrf`.
 */
struct bgp_per_src_nhg_hash_entry {
	uint32_t nhg_id;
	struct bgp *bgp;

	/* SOO Attr */
	struct ipaddr ip;
	afi_t afi;
	safi_t safi;

	/* back pointer for dest */
	struct bgp_dest *dest;

	struct bgp_nhg_nexthop_cache_head nhg_nexthop_cache_table;

	/* hash table of dest with soo attribute */
	struct hash *route_with_soo_table;

	uint32_t route_with_soo_use_nhid_cnt;

	bitfield_t bgp_soo_route_selected_pi_bitmap;
	bitfield_t bgp_soo_route_installed_pi_bitmap;

	uint32_t refcnt;

	bool soo_timer_running;

	uint32_t flags;

#define PER_SRC_NEXTHOP_GROUP_VALID		   (1 << 0)
#define PER_SRC_NEXTHOP_GROUP_INSTALL_PENDING	   (1 << 1)
#define PER_SRC_NEXTHOP_GROUP_DEL_PENDING	   (1 << 2)
#define PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_INSTALL	   (1 << 3)
#define PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_NHID_USED  (1 << 4)
#define PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_DO_WECMP   (1 << 5)
#define PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_CLEAR_ONLY (1 << 6)
#define PER_SRC_NEXTHOP_GROUP_SOO_ROUTE_ATTR_DEL   (1 << 7)
};

#define BGP_PER_SRC_NHG_SOO_TIMER_WHEEL_SLOTS 10
/* in milli seconds, total timer wheel period */
#define BGP_PER_SRC_NHG_SOO_TIMER_WHEEL_PERIOD 50

#endif /* _BGP_PER_SRC_NHG_H */
