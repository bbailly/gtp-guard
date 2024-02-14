/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of gtp-guard is to provide robust and secure
 *              extensions to GTP protocol (GPRS Tunneling Procol). GTP is
 *              widely used for data-plane in mobile core-network. gtp-guard
 *              implements a set of 3 main frameworks:
 *              A Proxy feature for data-plane tweaking, a Routing facility
 *              to inter-connect and a Firewall feature for filtering,
 *              rewriting and redirecting.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2023 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <libgen.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <libbpf.h>

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;

/* Local data */
static xdp_exported_maps_t xdp_rt_maps[XDP_RT_MAP_CNT];


/*
 *	XDP RT BPF related
 */
int
gtp_xdp_rt_load(gtp_bpf_opts_t *opts)
{
	struct bpf_map *map;
	int err;

	err = gtp_xdp_load(opts);
	if (err < 0)
		return -1;

	/* MAP ref for faster access */
	map = gtp_bpf_load_map(opts->bpf_obj, "teid_ingress");
	if (!map) {
		gtp_xdp_unload(opts);
		return -1;
	}
	xdp_rt_maps[XDP_RT_MAP_TEID_INGRESS].map = map;

	map = gtp_bpf_load_map(opts->bpf_obj, "teid_egress");
	if (!map) {
		gtp_xdp_unload(opts);
		return -1;
	}
	xdp_rt_maps[XDP_RT_MAP_TEID_EGRESS].map = map;

	map = gtp_bpf_load_map(opts->bpf_obj, "ppp_ingress");
	if (!map) {
		gtp_xdp_unload(opts);
		return -1;
	}
	xdp_rt_maps[XDP_RT_MAP_PPP_INGRESS].map = map;

	map = gtp_bpf_load_map(opts->bpf_obj, "ppp_egress");
	if (!map) {
		gtp_xdp_unload(opts);
		return -1;
	}
	xdp_rt_maps[XDP_RT_MAP_PPP_EGRESS].map = map;

	map = gtp_bpf_load_map(opts->bpf_obj, "iptnl_info");
	if (!map) {
		gtp_xdp_unload(opts);
		return -1;
	}
	xdp_rt_maps[XDP_RT_MAP_IPTNL].map = map;

	return 0;
}

void
gtp_xdp_rt_unload(gtp_bpf_opts_t *opts)
{
	gtp_xdp_unload(opts);
}


/*
 *	TEID Routing handling
 */
static struct gtp_rt_rule *
gtp_xdp_rt_rule_alloc(size_t *sz)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_rt_rule *new;

	new = calloc(nr_cpus, sizeof(*new));
	if (!new)
		return NULL;

	*sz = nr_cpus * sizeof(struct gtp_rt_rule);
	return new;
}

static void
gtp_xdp_rt_rule_set(struct gtp_rt_rule *r, gtp_teid_t *t)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	gtp_session_t *s = t->session;
	gtp_conn_t *c = s->conn;
	gtp_router_t *rtr = c->ctx;
	gtp_server_t *srv = &rtr->gtpu;
	ip_vrf_t *vrf = s->apn->vrf;
	__be32 dst_key = (vrf) ? vrf->id : 0;
	__u8 flags = __test_bit(IP_VRF_FL_IPIP_BIT, &vrf->flags) ? GTP_RT_FL_IPIP : 0;
	__u16 vlan_id = 0;
	int i;

	vlan_id = (vrf) ? vrf->encap_vlan_id : 0;
	if (__test_bit(GTP_TEID_FL_INGRESS, &t->flags))
		vlan_id = (vrf) ? vrf->decap_vlan_id : 0;

	for (i = 0; i < nr_cpus; i++) {
		r[i].teid = t->id;
		r[i].saddr = inet_sockaddrip4(&srv->addr);
		r[i].daddr = t->ipv4;
		r[i].dst_key = dst_key;
		r[i].vlan_id = vlan_id;
		r[i].packets = 0;
		r[i].bytes = 0;
		r[i].flags = flags;
	}
}

int
gtp_xdp_rt_key_set(gtp_teid_t *t, struct ip_rt_key *rt_key)
{
	gtp_session_t *s = t->session;
	gtp_conn_t *c = s->conn;
	gtp_router_t *r = c->ctx;
	gtp_server_t *srv = &r->gtpu;

	/* egress (upstream) : GTP TEID + pGW GTP Tunnel endpoint */
	if (__test_bit(GTP_TEID_FL_EGRESS, &t->flags)) {
		rt_key->id = t->id;
		rt_key->addr = inet_sockaddrip4(&srv->addr);
		return 0;
	}

	/* ingress (downstream) : session ipv4 address + IPIP or PPP tunnel endpoint */
	rt_key->id = 0;
	if (s->apn->vrf && __test_bit(IP_VRF_FL_IPIP_BIT, &s->apn->vrf->flags))
		rt_key->id = s->apn->vrf->iptnl.local_addr;
	rt_key->addr = s->ipv4;
	return 0;
}

static int
gtp_xdp_rt_action(int action, gtp_teid_t *t, struct bpf_map *map)
{
	struct gtp_rt_rule *new = NULL;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err = 0;
	struct ip_rt_key rt_key;
	size_t sz;

	/* If daemon is currently stopping, we simply skip action on ruleset.
	 * This reduce daemon exit time and entries are properly released during
	 * kernel BPF map release. */
	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		return 0;

	gtp_xdp_rt_key_set(t, &rt_key);

	/* Set rule */
	if (action == RULE_ADD) {
		/* fill per cpu rule */
		new = gtp_xdp_rt_rule_alloc(&sz);
		if (!new) {
			log_message(LOG_INFO, "%s(): Cant allocate teid_rule !!!"
					    , __FUNCTION__);
			err = -1;
			goto end;
		}
		gtp_xdp_rt_rule_set(new, t);
		err = bpf_map__update_elem(map, &rt_key, sizeof(struct ip_rt_key), new, sz, BPF_NOEXIST);
	} else if (action == RULE_DEL)
		err = bpf_map__delete_elem(map, &rt_key, sizeof(struct ip_rt_key), 0);
	else
		return -1;
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant %s XDP routing rule for TEID:0x%.8x (%s)"
				    , __FUNCTION__
				    , (action) ? "del" : "add"
				    , ntohl(t->id)
				    , errmsg);
		err = -1;
		goto end;
	}

	log_message(LOG_INFO, "%s(): %s %s XDP routing rule "
			      "{teid:0x%.8x, dst_addr:%u.%u.%u.%u}"
			    , __FUNCTION__
			    , (action) ? "deleting" : "adding"
			    , (__test_bit(GTP_TEID_FL_EGRESS, &t->flags)) ? "egress" : "ingress"
			    , ntohl(t->id), NIPQUAD(t->ipv4));
  end:
	if (new)
		free(new);
	return err;
}

static int
gtp_xdp_teid_vty(struct bpf_map *map, vty_t *vty, __be32 id)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct ip_rt_key key = { 0 }, next_key = { 0 };
	struct gtp_rt_rule *r;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	char addr_ip[16];
        int err = 0, i;
	uint64_t packets, bytes;
	size_t sz;

	/* Allocate temp rule */
	r = gtp_xdp_rt_rule_alloc(&sz);
	if (!r) {
		vty_out(vty, "%% Cant allocate temp rt_rule%s", VTY_NEWLINE);
		return -1;
	}

	/* Walk hashtab */
	while (bpf_map__get_next_key(map, &key, &next_key, sizeof(struct ip_rt_key)) == 0) {
		key = next_key;
		err = bpf_map__lookup_elem(map, &key, sizeof(struct ip_rt_key), r, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
			vty_out(vty, "%% error fetching value for key:0x%.8x (%s)%s"
				   , key.id, errmsg, VTY_NEWLINE);
			continue;
		}

		packets = bytes = 0;
		for (i = 0; i < nr_cpus; i++) {
			packets += r[i].packets;
			bytes += r[i].bytes;
		}

		vty_out(vty, "| 0x%.8x | %16s | %9s | %12ld | %19ld |%s"
			   , ntohl(r[0].teid)
			   , inet_ntoa2(r[0].daddr, addr_ip)
			   , (xdp_rt_maps[XDP_RT_MAP_TEID_EGRESS].map == map) ? "egress" : "ingress"
			   , packets, bytes
			   , VTY_NEWLINE);
	}

	free(r);
	return 0;
}

int
gtp_xdp_rt_teid_action(int action, gtp_teid_t *t)
{
	gtp_session_t *s;
	gtp_apn_t *apn;
	int direction;

	if (!__test_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags) || !t)
		return -1;

	direction = __test_bit(GTP_TEID_FL_EGRESS, &t->flags);
	s = t->session;
	apn = s->apn;

	/* PPPoE vrf ? */
	if (apn->vrf && __test_bit(IP_VRF_FL_PPPOE_BIT, &apn->vrf->flags))
		return gtp_xdp_ppp_action(action, t,
					  xdp_rt_maps[XDP_RT_MAP_PPP_INGRESS].map,
					  xdp_rt_maps[XDP_RT_MAP_PPP_EGRESS].map);

	return gtp_xdp_rt_action(action, t, xdp_rt_maps[direction].map);
}

int
gtp_xdp_rt_teid_vty(vty_t *vty, __be32 id)
{
	if (!__test_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags))
		return -1;

	return 0;
}

int
gtp_xdp_rt_vty(vty_t *vty)
{
	if (!__test_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags))
		return -1;

	vty_out(vty, "+------------+------------------+-----------+--------------+---------------------+%s"
		     "|    TEID    | Endpoint Address | Direction |   Packets    |        Bytes        |%s"
		     "+------------+------------------+-----------+--------------+---------------------+%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	gtp_xdp_teid_vty(xdp_rt_maps[XDP_RT_MAP_TEID_INGRESS].map, vty, 0);
	gtp_xdp_teid_vty(xdp_rt_maps[XDP_RT_MAP_TEID_EGRESS].map, vty, 0);
	vty_out(vty, "+------------+------------------+-----------+--------------+---------------------+%s"
		   , VTY_NEWLINE);
	return 0;
}

/*
 *	IP Tunneling related
 */
int
gtp_xdp_rt_iptnl_action(int action, gtp_iptnl_t *t)
{
	if (!__test_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags))
		return -1;

	return gtp_xdp_iptnl_action(action, t, xdp_rt_maps[XDP_RT_MAP_IPTNL].map);
}

int
gtp_xdp_rt_iptnl_vty(vty_t *vty)
{
	if (!__test_bit(GTP_FL_GTP_ROUTE_LOADED_BIT, &daemon_data->flags))
		return -1;

	return gtp_xdp_iptnl_vty(vty, xdp_rt_maps[XDP_RT_MAP_IPTNL].map);
}