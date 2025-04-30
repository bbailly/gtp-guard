/* system includes */
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"

int gtp_stats_init(gtp_server_stats_t *stats){
	stats->signalling_gtp = MALLOC(sizeof(gtp_signalling_gtp_stats_t));
	stats->signalling_pppoe = MALLOC(sizeof(gtp_signalling_pppoe_stats_t));
	stats->signalling_gtp->plmns = MALLOC(sizeof(gtp_htab_t));
	stats->signalling_pppoe->instances = MALLOC(sizeof(gtp_htab_t));
	gtp_htab_init(stats->signalling_gtp->plmns, STATS_GTP_PLMN_HASHTAB_SIZE);
	gtp_htab_init(stats->signalling_pppoe->instances, STATS_GTP_PPPOE_HASHTAB_SIZE);

	return 0;
}

int gtp_stats_destroy(gtp_server_stats_t *stats){
	gtp_plmn_stats_t *plmn_stats;
	gtp_ip_stats_t *ip_stats;
	struct hlist_node *n, *hl_tmp, *n1, *hl_tmp1;

	for (int i = 0; i < STATS_GTP_PLMN_HASHTAB_SIZE; i++) {
		hlist_for_each_entry_safe(plmn_stats, hl_tmp, n, &stats->signalling_gtp->plmns->htab[i], hlist){
			if(plmn_stats->peers){
				for (int j = 0; j < STATS_GTP_IP_HASHTAB_SIZE; j++) {
					hlist_for_each_entry_safe(ip_stats, hl_tmp1, n1, &plmn_stats->peers->htab[j], hlist){
						for (int k = 0; k < STATS_GTP_SIZE; k++) {
							if(ip_stats->v1_rx[k].causes){
								FREE(ip_stats->v1_rx[k].causes);
							}
							if(ip_stats->v1_tx[k].causes){
								FREE(ip_stats->v1_tx[k].causes);
							}
							if(ip_stats->v2_rx[k].causes){
								FREE(ip_stats->v2_rx[k].causes);
							}
							if(ip_stats->v2_tx[k].causes){
								FREE(ip_stats->v2_tx[k].causes);
							}
						}
						FREE(ip_stats->ip);
						FREE(ip_stats);
					}
				}
				gtp_htab_destroy(plmn_stats->peers);
				FREE(plmn_stats->peers);
			}
			for (int k = 0; k < STATS_GTP_SIZE; k++) {
				if(plmn_stats->v1_rx[k].causes){
					FREE(plmn_stats->v1_rx[k].causes);
				}
				if(plmn_stats->v1_tx[k].causes){
					FREE(plmn_stats->v1_tx[k].causes);
				}
				if(plmn_stats->v2_rx[k].causes){
					FREE(plmn_stats->v2_rx[k].causes);
				}
				if(plmn_stats->v2_tx[k].causes){
					FREE(plmn_stats->v2_tx[k].causes);
				}
			}
			FREE(plmn_stats->plmn);
			FREE(plmn_stats);
		}
	}
	gtp_htab_destroy(stats->signalling_gtp->plmns);
	FREE(stats->signalling_gtp->plmns);


	for (int k = 0; k < STATS_GTP_SIZE; k++) {
		if(stats->signalling_gtp->v1_rx[k].causes){
			FREE(stats->signalling_gtp->v1_rx[k].causes);
		}
		if(stats->signalling_gtp->v1_tx[k].causes){
			FREE(stats->signalling_gtp->v1_tx[k].causes);
		}
		if(stats->signalling_gtp->v2_rx[k].causes){
			FREE(stats->signalling_gtp->v2_rx[k].causes);
		}
		if(stats->signalling_gtp->v2_tx[k].causes){
			FREE(stats->signalling_gtp->v2_tx[k].causes);
		}
	}

	gtp_htab_destroy(stats->signalling_pppoe->instances);
	FREE(stats->signalling_pppoe->instances);
	FREE(stats->signalling_pppoe);
	FREE(stats->signalling_gtp);

	return 0;
}

static struct hlist_head *
gtp_stats_plmn_hashkey(gtp_htab_t *h, uint8_t *plmn)
{
	/* TODO maybe to compare using one 32 bits word and not 3 8 bits words */
	return h->htab + (jhash_3words(plmn[0],plmn[1],plmn[2], 0) & STATS_GTP_PLMN_HASHTAB_MASK);
}

static struct hlist_head *
gtp_stats_ip_hashkey(gtp_htab_t *h, struct sockaddr_storage *ip)
{
	if(ip->ss_family == AF_INET){
		return h->htab + (jhash_1word(((struct sockaddr_in*)ip)->sin_addr.s_addr, 0) & STATS_GTP_IP_HASHTAB_MASK);
	}else if (ip->ss_family == AF_INET6){
		return h->htab + (jhash2(((struct sockaddr_in6*)ip)->sin6_addr.__in6_u.__u6_addr32, 16, 0) & STATS_GTP_IP_HASHTAB_MASK);
	} else {
		return NULL;
	}
}


 gtp_ip_stats_t *
 __gtp_stats_ip_hash(gtp_htab_t *h, struct sockaddr_storage *ip)
 {
	 struct hlist_head *ip_stats_head;
	 gtp_ip_stats_t *ip_stats;
	 ip_stats_head = gtp_stats_ip_hashkey(h, ip);
 
	 struct hlist_node *n;
	 hlist_for_each_entry(ip_stats, n, ip_stats_head, hlist){
		switch (ip_stats->ip->ss_family)
		{
		case AF_INET:
			if(((struct sockaddr_in *)ip_stats->ip)->sin_addr.s_addr == ((struct sockaddr_in *)ip)->sin_addr.s_addr){
				return ip_stats;
			}
			break;
		default:
			return NULL;
		}
	 }
	ip_stats = MALLOC(sizeof(gtp_plmn_stats_t));
	switch(ip->ss_family)
	{
		case AF_INET:
			ip_stats->ip = MALLOC(sizeof(struct sockaddr_in));
			((struct sockaddr_in *)ip_stats->ip)->sin_family = ((struct sockaddr_in *)ip)->sin_family;
			((struct sockaddr_in *)ip_stats->ip)->sin_addr = ((struct sockaddr_in *)ip)->sin_addr;
			((struct sockaddr_in *)ip_stats->ip)->sin_port = 0;
			break;
		default:
			return NULL;
	}
	hlist_add_head(&ip_stats->hlist, ip_stats_head);
	return ip_stats;
 }
 
 gtp_plmn_stats_t *
__gtp_stats_plmn_hash(gtp_htab_t *h, uint8_t *plmn)
{
	struct hlist_head *plmn_stats_head;
	gtp_plmn_stats_t *plmn_stats;
	plmn_stats_head = gtp_stats_plmn_hashkey(h, plmn);

	struct hlist_node *n;
	hlist_for_each_entry(plmn_stats, n, plmn_stats_head, hlist){
		if(!memcmp(plmn_stats->plmn, plmn, GTP_PLMN_MAX_LEN)){
			return plmn_stats;
		}
	}
	plmn_stats = MALLOC(sizeof(gtp_plmn_stats_t));
	plmn_stats->plmn = MALLOC(GTP_PLMN_MAX_LEN);
	memcpy(plmn_stats->plmn, plmn, GTP_PLMN_MAX_LEN);
	plmn_stats->peers = MALLOC(sizeof(gtp_htab_t));
	gtp_htab_init(plmn_stats->peers, STATS_GTP_IP_HASHTAB_SIZE);
	hlist_add_head(&plmn_stats->hlist, plmn_stats_head);
	return plmn_stats;
}

void __gtp_stats_gtp_inc_dropped(gtp_gtp_stats_t *stats, uint8_t version, uint8_t message_type){
	if(version == 1){
		stats->v1_rx[message_type].dropped++;
	}else if(version == 2){
		stats->v2_rx[message_type].dropped++;
	}
}


void __gtp_stats_gtp_signalling_inc_dropped(gtp_gtp_stats_t *stats, uint8_t version, uint8_t message_type){
	__gtp_stats_gtp_inc_dropped(stats, version, message_type);
}

void gtp_stats_gtp_signalling_inc_dropped(gtp_server_stats_t *server_stats, uint8_t *peer_plmn, struct sockaddr_storage *peer_ip, uint8_t version, uint8_t message_type){
	gtp_plmn_stats_t *plmn_stats = NULL;
	gtp_ip_stats_t *ip_stats = NULL;
	uint32_t plmn_hash = 0;
	uint32_t ip_hash;

	__gtp_stats_gtp_signalling_inc_dropped((gtp_gtp_stats_t *)server_stats->signalling_gtp, version, message_type);
	if(peer_plmn){
		memcpy(&plmn_hash, peer_plmn, GTP_PLMN_MAX_LEN);
		dlock_lock_id(server_stats->signalling_gtp->plmns->dlock, plmn_hash, 0);
		plmn_stats = __gtp_stats_plmn_hash(server_stats->signalling_gtp->plmns, peer_plmn);
		__gtp_stats_gtp_signalling_inc_dropped((gtp_gtp_stats_t *)plmn_stats, version, message_type);
		if(peer_ip){
			ip_hash = peer_ip->ss_family == AF_INET ? (((struct sockaddr_in *)peer_ip)->sin_addr.s_addr) : (((struct sockaddr_in6 *)peer_ip)->sin6_addr.__in6_u.__u6_addr32[0]);
			dlock_lock_id(plmn_stats->peers->dlock, ip_hash, 0);
			ip_stats = __gtp_stats_ip_hash(plmn_stats->peers, peer_ip);
			__gtp_stats_gtp_signalling_inc_dropped((gtp_gtp_stats_t *)ip_stats, version, message_type);
			dlock_unlock_id(plmn_stats->peers->dlock, ip_hash, 0);
		}
		dlock_unlock_id(server_stats->signalling_gtp->plmns->dlock, plmn_hash, 0);
	}
}

void __gtp_stats_gtp_inc_unsupported(gtp_gtp_stats_t *stats, uint8_t version, uint8_t message_type){
	if(version == 1){
		stats->v1_rx[message_type].unsupported++;
	}else if(version == 2){
		stats->v2_rx[message_type].unsupported++;
	}
}


void __gtp_stats_gtp_signalling_inc_unsupported(gtp_gtp_stats_t *stats, uint8_t version, uint8_t message_type){
	__gtp_stats_gtp_inc_unsupported(stats, version, message_type);
}

void gtp_stats_gtp_signalling_inc_unsupported(gtp_server_stats_t *server_stats, uint8_t *peer_plmn, struct sockaddr_storage *peer_ip, uint8_t version, uint8_t message_type){
	gtp_plmn_stats_t *plmn_stats = NULL;
	gtp_ip_stats_t *ip_stats = NULL;
	uint32_t plmn_hash = 0;
	uint32_t ip_hash;

	__gtp_stats_gtp_signalling_inc_unsupported((gtp_gtp_stats_t *)server_stats->signalling_gtp, version, message_type);
	if(peer_plmn){
		memcpy(&plmn_hash, peer_plmn, GTP_PLMN_MAX_LEN);
		dlock_lock_id(server_stats->signalling_gtp->plmns->dlock, plmn_hash, 0);
		plmn_stats = __gtp_stats_plmn_hash(server_stats->signalling_gtp->plmns, peer_plmn);
		__gtp_stats_gtp_signalling_inc_unsupported((gtp_gtp_stats_t *)plmn_stats, version, message_type);
		if(peer_ip){
			ip_hash = peer_ip->ss_family == AF_INET ? (((struct sockaddr_in *)peer_ip)->sin_addr.s_addr) : (((struct sockaddr_in6 *)peer_ip)->sin6_addr.__in6_u.__u6_addr32[0]);
			dlock_lock_id(plmn_stats->peers->dlock, ip_hash, 0);
			ip_stats = __gtp_stats_ip_hash(plmn_stats->peers, peer_ip);
			__gtp_stats_gtp_signalling_inc_unsupported((gtp_gtp_stats_t *)ip_stats, version, message_type);
			dlock_unlock_id(plmn_stats->peers->dlock, ip_hash, 0);
		}
		dlock_unlock_id(server_stats->signalling_gtp->plmns->dlock, plmn_hash, 0);
	}
}

void __gtp_stats_gtp_inc_counter(gtp_gtp_stats_t *stats, uint8_t version, direction_t direction, uint8_t message_type, uint8_t *cause){
	if(version == 1){
		if(direction == DIR_RX){
			stats->v1_rx[message_type].counter++;
			if(cause){
				if(!stats->v1_rx[message_type].causes){
					stats->v1_rx[message_type].causes = MALLOC(sizeof(uint64_t[STATS_GTP_SIZE]));
				}
				stats->v1_rx[message_type].causes[*cause]++;
			}
		}else{
			stats->v1_tx[message_type].counter++;
			if(cause){
				if(!stats->v1_tx[message_type].causes){
					stats->v1_tx[message_type].causes = MALLOC(sizeof(uint64_t[STATS_GTP_SIZE]));
				}
				stats->v1_tx[message_type].causes[*cause]++;
			}
		}
	}else if(version == 2){
		if(direction == DIR_RX){
			stats->v2_rx[message_type].counter++;
			if(cause){
				if(!stats->v2_rx[message_type].causes){
					stats->v2_rx[message_type].causes = MALLOC(sizeof(uint64_t[STATS_GTP_SIZE]));
				}
				stats->v2_rx[message_type].causes[*cause]++;
			}
		}else{
			stats->v2_tx[message_type].counter++;
			if(cause){
				if(!stats->v2_tx[message_type].causes){
					stats->v2_tx[message_type].causes = MALLOC(sizeof(uint64_t[STATS_GTP_SIZE]));
				}
				stats->v2_tx[message_type].causes[*cause]++;
			}
		}
	}
}


void __gtp_stats_gtp_signalling_inc_counter(gtp_gtp_stats_t *stats, uint8_t version, direction_t direction, uint8_t message_type, uint8_t *cause){
	__gtp_stats_gtp_inc_counter(stats, version, direction, message_type, cause);
}

void gtp_stats_gtp_signalling_inc_counter(gtp_server_stats_t *server_stats, uint8_t *peer_plmn, struct sockaddr_storage *peer_ip, uint8_t version, direction_t direction, uint8_t message_type, uint8_t *cause){
	gtp_plmn_stats_t *plmn_stats = NULL;
	gtp_ip_stats_t *ip_stats = NULL;
	uint32_t plmn_hash = 0;
	uint32_t ip_hash;

	__gtp_stats_gtp_signalling_inc_counter((gtp_gtp_stats_t *)server_stats->signalling_gtp, version, direction, message_type, cause);

	if(peer_plmn){
		memcpy(&plmn_hash, peer_plmn, GTP_PLMN_MAX_LEN);
		dlock_lock_id(server_stats->signalling_gtp->plmns->dlock, plmn_hash, 0);
		plmn_stats = __gtp_stats_plmn_hash(server_stats->signalling_gtp->plmns, peer_plmn);
		__gtp_stats_gtp_signalling_inc_counter((gtp_gtp_stats_t *)plmn_stats, version, direction, message_type, cause);
		if(peer_ip){
			ip_hash = peer_ip->ss_family == AF_INET ? (((struct sockaddr_in *)peer_ip)->sin_addr.s_addr) : (((struct sockaddr_in6 *)peer_ip)->sin6_addr.__in6_u.__u6_addr32[0]);
			dlock_lock_id(plmn_stats->peers->dlock, ip_hash, 0);
			ip_stats = __gtp_stats_ip_hash(plmn_stats->peers, peer_ip);
			__gtp_stats_gtp_signalling_inc_counter((gtp_gtp_stats_t *)ip_stats, version, direction, message_type,cause);
			dlock_unlock_id(plmn_stats->peers->dlock, ip_hash, 0);
		}
		dlock_unlock_id(server_stats->signalling_gtp->plmns->dlock, plmn_hash, 0);
	}
}

void __gtp_stats_gtp_sessions_by_type_add(gtp_server_stats_t *server_stats, uint8_t *peer_plmn, struct sockaddr_storage *peer_ip, session_type_t session_type, int value){
	server_stats->signalling_gtp->sessions_by_type[session_type] += value;
	gtp_plmn_stats_t *plmn_stats = NULL;
	gtp_ip_stats_t *ip_stats = NULL;
	uint32_t plmn_hash = 0;
	uint32_t ip_hash;

	if(peer_plmn){
		memcpy(&plmn_hash, peer_plmn, GTP_PLMN_MAX_LEN);
		dlock_lock_id(server_stats->signalling_gtp->plmns->dlock, plmn_hash, 0);
		plmn_stats = __gtp_stats_plmn_hash(server_stats->signalling_gtp->plmns, peer_plmn);
		plmn_stats->sessions_by_type[session_type] += value;
		if(peer_ip){
			ip_hash = peer_ip->ss_family == AF_INET ? (((struct sockaddr_in *)peer_ip)->sin_addr.s_addr) : (((struct sockaddr_in6 *)peer_ip)->sin6_addr.__in6_u.__u6_addr32[0]);
			dlock_lock_id(plmn_stats->peers->dlock, ip_hash, 0);
			ip_stats = __gtp_stats_ip_hash(plmn_stats->peers, peer_ip);
			ip_stats->sessions_by_type[session_type] += value;
			dlock_unlock_id(plmn_stats->peers->dlock, ip_hash, 0);
		}
		dlock_unlock_id(server_stats->signalling_gtp->plmns->dlock, plmn_hash, 0);
	}

}


void gtp_stats_gtp_sessions_by_type_inc(gtp_server_stats_t *server_stats, uint8_t *peer_plmn, struct sockaddr_storage *peer_ip, session_type_t session_type){
	__gtp_stats_gtp_sessions_by_type_add(server_stats, peer_plmn, peer_ip, session_type, 1);
}

void gtp_stats_gtp_sessions_by_type_dec(gtp_server_stats_t *server_stats, uint8_t *peer_plmn, struct sockaddr_storage *peer_ip, session_type_t session_type){
	__gtp_stats_gtp_sessions_by_type_add(server_stats, peer_plmn, peer_ip, session_type, -1);
}

void __gtp_stats_gtp_sessions_by_rattype_add(gtp_server_stats_t *server_stats, uint8_t *peer_plmn, struct sockaddr_storage *peer_ip, rat_type_t rat_type, int value){
	server_stats->signalling_gtp->sessions_by_rattype[rat_type] += value;
	gtp_plmn_stats_t *plmn_stats = NULL;
	gtp_ip_stats_t *ip_stats = NULL;
	uint32_t plmn_hash = 0;
	uint32_t ip_hash;

	if(peer_plmn){
		memcpy(&plmn_hash, peer_plmn, GTP_PLMN_MAX_LEN);
		dlock_lock_id(server_stats->signalling_gtp->plmns->dlock, plmn_hash, 0);
		plmn_stats = __gtp_stats_plmn_hash(server_stats->signalling_gtp->plmns, peer_plmn);
		plmn_stats->sessions_by_rattype[rat_type] += value;
		if(peer_ip){
			ip_hash = peer_ip->ss_family == AF_INET ? (((struct sockaddr_in *)peer_ip)->sin_addr.s_addr) : (((struct sockaddr_in6 *)peer_ip)->sin6_addr.__in6_u.__u6_addr32[0]);
			dlock_lock_id(plmn_stats->peers->dlock, ip_hash, 0);
			ip_stats = __gtp_stats_ip_hash(plmn_stats->peers, peer_ip);
			ip_stats->sessions_by_rattype[rat_type] += value;
			dlock_unlock_id(plmn_stats->peers->dlock, ip_hash, 0);
		}
		dlock_unlock_id(server_stats->signalling_gtp->plmns->dlock, plmn_hash, 0);
	}

}


void gtp_stats_gtp_sessions_by_rattype_inc(gtp_server_stats_t *server_stats, uint8_t *peer_plmn, struct sockaddr_storage *peer_ip, rat_type_t rat_type){
	__gtp_stats_gtp_sessions_by_rattype_add(server_stats, peer_plmn, peer_ip, rat_type, 1);
}

void gtp_stats_gtp_sessions_by_rattype_dec(gtp_server_stats_t *server_stats, uint8_t *peer_plmn, struct sockaddr_storage *peer_ip, rat_type_t rat_type){
	__gtp_stats_gtp_sessions_by_rattype_add(server_stats, peer_plmn, peer_ip, rat_type, -1);
}





cmd_node_t stats_node = {
	.node = STATS_NODE,
	.parent_node = ENABLE_NODE,
	.prompt = "%s# ",
};
extern data_t *daemon_data;

void __gtp_sum_stats(gtp_stats_t sum[], gtp_stats_t src[], uint8_t length){
	for(int i=0; i<length; i++){
		sum[i].counter += src[i].counter;
		sum[i].unsupported += src[i].unsupported;
		sum[i].dropped += src[i].dropped;
		if(src[i].causes){
			if(!sum[i].causes){
				sum[i].causes = MALLOC(sizeof(uint64_t[STATS_GTP_SIZE]));
			}
			for(int j=0; j<STATS_GTP_SIZE; j++){
				sum[i].causes[j] = src[i].causes[j];
			}
		}
	}
}



void __gtp_stats_show_gtp_server(gtp_server_t *srv, uint8_t *plmn, gtp_htab_t *tmp_plmns, gtp_htab_t *tmp_ips, gtp_stats_t *stats_v1_rx, gtp_stats_t *stats_v1_tx, gtp_stats_t *stats_v2_rx, gtp_stats_t *stats_v2_tx){
	gtp_server_worker_t *worker, *w_tmp;
	gtp_plmn_stats_t *plmn_stats;
	gtp_ip_stats_t *ip_stats;
	gtp_plmn_stats_t *tmp_plmn_stats;
	gtp_ip_stats_t *tmp_ip_stats;
	struct hlist_node *n, *hl_tmp;

	list_for_each_entry_safe(worker, w_tmp, &srv->workers, next){
		if(plmn){
			struct hlist_head *plmn_stats_head;
			plmn_stats_head = gtp_stats_plmn_hashkey(worker->stats.signalling_gtp->plmns, plmn);

			hlist_for_each_entry_safe(plmn_stats, hl_tmp, n, plmn_stats_head, hlist){
				if(memcmp(plmn_stats->plmn, plmn, GTP_PLMN_MAX_LEN)){
					continue;
				}
				__gtp_sum_stats(stats_v1_rx, plmn_stats->v1_rx, STATS_GTP_SIZE);
				__gtp_sum_stats(stats_v1_tx, plmn_stats->v1_tx, STATS_GTP_SIZE);
				__gtp_sum_stats(stats_v2_rx, plmn_stats->v2_rx, STATS_GTP_SIZE);
				__gtp_sum_stats(stats_v2_tx, plmn_stats->v2_tx, STATS_GTP_SIZE);

				for (int i = 0; i < STATS_GTP_IP_HASHTAB_SIZE; i++) {
					hlist_for_each_entry_safe(ip_stats, hl_tmp, n, &plmn_stats->peers->htab[i], hlist){
						tmp_ip_stats = __gtp_stats_ip_hash(tmp_ips, ip_stats->ip);
						__gtp_sum_stats(tmp_ip_stats->v1_rx, ip_stats->v1_rx, STATS_GTP_SIZE);
						__gtp_sum_stats(tmp_ip_stats->v1_tx, ip_stats->v1_tx, STATS_GTP_SIZE);
						__gtp_sum_stats(tmp_ip_stats->v2_rx, ip_stats->v2_rx, STATS_GTP_SIZE);
						__gtp_sum_stats(tmp_ip_stats->v2_tx, ip_stats->v2_tx, STATS_GTP_SIZE);
					}
				}
			}
		}else{
			__gtp_sum_stats(stats_v1_rx, worker->stats.signalling_gtp->v1_rx, STATS_GTP_SIZE);
			__gtp_sum_stats(stats_v1_tx, worker->stats.signalling_gtp->v1_tx, STATS_GTP_SIZE);
			__gtp_sum_stats(stats_v2_rx, worker->stats.signalling_gtp->v2_rx, STATS_GTP_SIZE);
			__gtp_sum_stats(stats_v2_tx, worker->stats.signalling_gtp->v2_tx, STATS_GTP_SIZE);
			for (int i = 0; i < STATS_GTP_PLMN_HASHTAB_SIZE; i++) {
				hlist_for_each_entry_safe(plmn_stats, hl_tmp, n, &worker->stats.signalling_gtp->plmns->htab[i], hlist){
					tmp_plmn_stats = __gtp_stats_plmn_hash(tmp_plmns, plmn_stats->plmn);
					__gtp_sum_stats(tmp_plmn_stats->v1_rx, plmn_stats->v1_rx, STATS_GTP_SIZE);
					__gtp_sum_stats(tmp_plmn_stats->v1_tx, plmn_stats->v1_tx, STATS_GTP_SIZE);
					__gtp_sum_stats(tmp_plmn_stats->v2_rx, plmn_stats->v2_rx, STATS_GTP_SIZE);
					__gtp_sum_stats(tmp_plmn_stats->v2_tx, plmn_stats->v2_tx, STATS_GTP_SIZE);
				}
			}
		}
	}
}

static int
gtp_stats_gtp_show(vty_t *vty, uint8_t *plmn)
{
	const list_head_t *l = &daemon_data->gtp_switch_ctx;
	gtp_switch_t *ctx;
	gtp_plmn_stats_t *plmn_stats;
	gtp_ip_stats_t *ip_stats;
	struct hlist_node *n;
	struct hlist_node *hl_tmp;
	gtp_htab_t *tmp_plmns = NULL;
	gtp_htab_t *tmp_ips = NULL;
	uint8_t unknown_plmn[GTP_PLMN_MAX_LEN] = {0};


	gtp_stats_t stats_v1_rx[STATS_GTP_SIZE] = {0};
	gtp_stats_t stats_v1_tx[STATS_GTP_SIZE] = {0};
	gtp_stats_t stats_v2_rx[STATS_GTP_SIZE] = {0};
	gtp_stats_t stats_v2_tx[STATS_GTP_SIZE] = {0};

	if(plmn){
		tmp_ips = MALLOC(sizeof(gtp_htab_t));
		gtp_htab_init(tmp_ips, STATS_GTP_IP_HASHTAB_SIZE);
	}else{
		tmp_plmns = MALLOC(sizeof(gtp_htab_t));
		gtp_htab_init(tmp_plmns, STATS_GTP_PLMN_HASHTAB_SIZE);
	}

	list_for_each_entry(ctx, l, next) {
		__gtp_stats_show_gtp_server(&ctx->gtpc, plmn, tmp_plmns, tmp_ips, stats_v1_rx, stats_v1_tx, stats_v2_rx, stats_v2_tx);
		if (__test_bit(GTP_FL_CTL_BIT, &ctx->gtpc_egress.flags)) {
			__gtp_stats_show_gtp_server(&ctx->gtpc_egress, plmn, tmp_plmns, tmp_ips, stats_v1_rx, stats_v1_tx, stats_v2_rx, stats_v2_tx);
		}
		if(plmn){
			vty_out(vty, "\t\t\t\t\trx\ttx\tdrp%s", VTY_NEWLINE);
			for(int j=0; j < STATS_GTP_SIZE; j++){
				if(stats_v1_rx[j].counter > 0 || stats_v1_tx[j].counter > 0 || stats_v1_rx[j].dropped > 0){
					vty_out(vty, "%-39.39s :\t%lu\t%lu\t%lu%s", gtp1c_msg_type2str[j].name, stats_v1_rx[j].counter, stats_v1_tx[j].counter, stats_v1_rx[j].dropped, VTY_NEWLINE);
					for(int k=0; k < STATS_GTP_SIZE; k++){
						if((stats_v1_rx[j].causes && stats_v1_rx[j].causes[k] > 0) || (stats_v1_tx[j].causes && stats_v1_tx[j].causes[k] > 0))
							vty_out(vty, "|_%-35.35s :\t%lu\t%lu%s", gtp1c_msg_cause2str[k].name, stats_v1_rx[j].causes?stats_v1_rx[j].causes[k]:0, stats_v1_tx[j].causes?stats_v1_tx[j].causes[k]:0, VTY_NEWLINE);
					}
				}
			}
			for(int j=0; j < STATS_GTP_SIZE; j++){
				if(stats_v2_rx[j].counter > 0 || stats_v2_tx[j].counter > 0 || stats_v2_rx[j].dropped > 0){
					vty_out(vty, "%-37.37s :\t%lu\t%lu\t%lu%s", gtp2c_msg_type2str[j].name, stats_v2_rx[j].counter, stats_v2_tx[j].counter, stats_v2_rx[j].dropped, VTY_NEWLINE);
					for(int k=0; k < STATS_GTP_SIZE; k++){
						if((stats_v2_rx[j].causes && stats_v2_rx[j].causes[k] > 0) || (stats_v2_tx[j].causes && stats_v2_tx[j].causes[k] > 0))
							vty_out(vty, "|_%-35.35s :\t%lu\t%lu%s", gtp2c_msg_cause2str[k].name, stats_v2_rx[j].causes?stats_v2_rx[j].causes[k]:0, stats_v2_tx[j].causes?stats_v2_tx[j].causes[k]:0, VTY_NEWLINE);
					}
				}
			}
			for (int i = 0; i < STATS_GTP_IP_HASHTAB_SIZE; i++) {
				hlist_for_each_entry_safe(ip_stats, hl_tmp, n, &tmp_ips->htab[i], hlist){
					vty_out(vty, "IP %u.%u.%u.%u%s", NIPQUAD(((struct sockaddr_in *)ip_stats->ip)->sin_addr), VTY_NEWLINE);
					for(int j=0; j < STATS_GTP_SIZE; j++){
						if(ip_stats->v1_rx[j].counter > 0 || ip_stats->v1_tx[j].counter > 0 || ip_stats->v1_rx[j].dropped > 0){
							vty_out(vty, "|_%-35.35s :\t%lu\t%lu\t%lu%s", gtp1c_msg_type2str[j].name, ip_stats->v1_rx[j].counter, ip_stats->v1_tx[j].counter, ip_stats->v1_rx[j].dropped, VTY_NEWLINE);
							for(int k=0; k < STATS_GTP_SIZE; k++){
								if((ip_stats->v1_rx[j].causes && ip_stats->v1_rx[j].causes[k] > 0) || (ip_stats->v1_tx[j].causes && ip_stats->v1_tx[j].causes[k] > 0)){
									if(gtp1c_msg_cause2str[k].name){
										vty_out(vty, "  |_%-33.33s :\t%lu\t%lu%s", gtp1c_msg_cause2str[k].name, ip_stats->v1_rx[j].causes?ip_stats->v1_rx[j].causes[k]:0, ip_stats->v1_tx[j].causes?ip_stats->v1_tx[j].causes[k]:0, VTY_NEWLINE);
									}else{
										vty_out(vty, "  |_cause %-27.27d :\t%lu\t%lu%s", k, ip_stats->v1_rx[j].causes?ip_stats->v1_rx[j].causes[k]:0, ip_stats->v1_tx[j].causes?ip_stats->v1_tx[j].causes[k]:0, VTY_NEWLINE);
									}
								}
							}
						}
					}
					for(int j=0; j < STATS_GTP_SIZE; j++){
						if(ip_stats->v2_rx[j].counter > 0 || ip_stats->v2_tx[j].counter > 0 || ip_stats->v2_rx[j].dropped > 0){
							vty_out(vty, "|_%-35.35s :\t%lu\t%lu\t%lu%s", gtp2c_msg_type2str[j].name, ip_stats->v2_rx[j].counter, ip_stats->v2_tx[j].counter, ip_stats->v2_rx[j].dropped, VTY_NEWLINE);
							for(int k=0; k < STATS_GTP_SIZE; k++){
								if((ip_stats->v2_rx[j].causes && ip_stats->v2_rx[j].causes[k] > 0) || (ip_stats->v2_tx[j].causes && ip_stats->v2_tx[j].causes[k] > 0)){
									if(gtp2c_msg_cause2str[k].name){
										vty_out(vty, "  |_%-33.33s :\t%lu\t%lu%s", gtp2c_msg_cause2str[k].name, ip_stats->v2_rx[j].causes?ip_stats->v2_rx[j].causes[k]:0, ip_stats->v2_tx[j].causes?ip_stats->v2_tx[j].causes[k]:0, VTY_NEWLINE);
									}else{
										vty_out(vty, "  |_cause %-27.27d :\t%lu\t%lu%s", k, ip_stats->v2_rx[j].causes?ip_stats->v2_rx[j].causes[k]:0, ip_stats->v2_tx[j].causes?ip_stats->v2_tx[j].causes[k]:0, VTY_NEWLINE);
									}
								}
							}
						}
					}
					for (int k = 0; k < STATS_GTP_SIZE; k++) {
						if(ip_stats->v1_rx[0].causes)
							FREE(ip_stats->v1_rx[0].causes);
						if(ip_stats->v1_tx[0].causes)
							FREE(ip_stats->v1_tx[0].causes);
						if(ip_stats->v2_rx[0].causes)
							FREE(ip_stats->v1_rx[0].causes);
						if(ip_stats->v2_tx[0].causes)
							FREE(ip_stats->v2_tx[0].causes);
					}
					FREE(ip_stats->ip);
					FREE(ip_stats);
				}
			}
		}else{
			vty_out(vty, "\t\t\t\t\trx\ttx\tdrp%s", VTY_NEWLINE);
			for(int j=0; j < STATS_GTP_SIZE; j++){
				if(stats_v1_rx[j].counter > 0 || stats_v1_tx[j].counter > 0 || stats_v1_rx[j].dropped > 0){
					vty_out(vty, "%-37.37s :\t%lu\t%lu\t%lu%s", gtp1c_msg_type2str[j].name, stats_v1_rx[j].counter, stats_v1_tx[j].counter, stats_v1_rx[j].dropped, VTY_NEWLINE);
					for(int k=0; k < STATS_GTP_SIZE; k++){
						if((stats_v1_rx[j].causes && stats_v1_rx[j].causes[k] > 0) || (stats_v1_tx[j].causes && stats_v1_tx[j].causes[k] > 0))
							vty_out(vty, "|_%-35.35s :\t%lu\t%lu%s", gtp1c_msg_cause2str[k].name, stats_v1_rx[j].causes?stats_v1_rx[j].causes[k]:0, stats_v1_tx[j].causes?stats_v1_tx[j].causes[k]:0, VTY_NEWLINE);
					}
				}
			}
			for(int j=0; j < STATS_GTP_SIZE; j++){
				if(stats_v2_rx[j].counter > 0 || stats_v2_tx[j].counter > 0 || stats_v2_rx[j].dropped > 0){
					vty_out(vty, "%-37.37s :\t%lu\t%lu\t%lu%s", gtp2c_msg_type2str[j].name, stats_v2_rx[j].counter, stats_v2_tx[j].counter, stats_v2_rx[j].dropped, VTY_NEWLINE);
					for(int k=0; k < STATS_GTP_SIZE; k++){
						if((stats_v2_rx[j].causes && stats_v2_rx[j].causes[k] > 0) || (stats_v2_tx[j].causes && stats_v2_tx[j].causes[k] > 0))
							vty_out(vty, "|_%-35.35s :\t%lu\t%lu%s", gtp2c_msg_cause2str[k].name, stats_v2_rx[j].causes?stats_v2_rx[j].causes[k]:0, stats_v2_tx[j].causes?stats_v2_tx[j].causes[k]:0, VTY_NEWLINE);
					}

				}
			}
			for (int i = 0; i < STATS_GTP_PLMN_HASHTAB_SIZE; i++) {
				hlist_for_each_entry_safe(plmn_stats, hl_tmp, n, &tmp_plmns->htab[i], hlist){
					char splmn_s[7];
					if(!memcmp(plmn_stats->plmn, unknown_plmn, GTP_PLMN_MAX_LEN)){
						vty_out(vty, "PLMN UNKNOWN%s", VTY_NEWLINE);
					}else{
						plmn_bcd_to_string(plmn_stats->plmn, splmn_s);
						vty_out(vty, "PLMN %s%s", splmn_s, VTY_NEWLINE);
					}
					for(int j=0; j < STATS_GTP_SIZE; j++){
						if(plmn_stats->v1_rx[j].counter > 0 || plmn_stats->v1_tx[j].counter > 0 || plmn_stats->v1_rx[j].dropped > 0){
							vty_out(vty, "|_%-35.35s :\t%lu\t%lu\t%lu%s", gtp1c_msg_type2str[j].name, plmn_stats->v1_rx[j].counter, plmn_stats->v1_tx[j].counter, plmn_stats->v1_rx[j].dropped, VTY_NEWLINE);
							for(int k=0; k < STATS_GTP_SIZE; k++){
								if((plmn_stats->v1_rx[j].causes && plmn_stats->v1_rx[j].causes[k] > 0) || (plmn_stats->v1_tx[j].causes && plmn_stats->v1_tx[j].causes[k] > 0)){
									if(gtp1c_msg_cause2str[k].name){
										vty_out(vty, "  |_%-33.33s :\t%lu\t%lu%s", gtp1c_msg_cause2str[k].name, plmn_stats->v1_rx[j].causes?plmn_stats->v1_rx[j].causes[k]:0, plmn_stats->v1_tx[j].causes?plmn_stats->v1_tx[j].causes[k]:0, VTY_NEWLINE);
									}else{
										vty_out(vty, "  |_cause %-27.27d :\t%lu\t%lu%s", k, plmn_stats->v1_rx[j].causes?plmn_stats->v1_rx[j].causes[k]:0, plmn_stats->v1_tx[j].causes?plmn_stats->v1_tx[j].causes[k]:0, VTY_NEWLINE);
									}
								}
							}
						}
					}
					for(int j=0; j < STATS_GTP_SIZE; j++){
						if(plmn_stats->v2_rx[j].counter > 0 || plmn_stats->v2_tx[j].counter > 0 || plmn_stats->v2_rx[j].dropped > 0){
							vty_out(vty, "|_%-35.35s :\t%lu\t%lu\t%lu%s", gtp2c_msg_type2str[j].name, plmn_stats->v2_rx[j].counter, plmn_stats->v2_tx[j].counter, plmn_stats->v2_rx[j].dropped, VTY_NEWLINE);
							for(int k=0; k < STATS_GTP_SIZE; k++){
								if((plmn_stats->v2_rx[j].causes && plmn_stats->v2_rx[j].causes[k] > 0) || (plmn_stats->v2_tx[j].causes && plmn_stats->v2_tx[j].causes[k] > 0)){
									if(gtp2c_msg_cause2str[k].name){
										vty_out(vty, "  |_%-33.33s :\t%lu\t%lu%s", gtp2c_msg_cause2str[k].name, plmn_stats->v2_rx[j].causes?plmn_stats->v2_rx[j].causes[k]:0, plmn_stats->v2_tx[j].causes?plmn_stats->v2_tx[j].causes[k]:0, VTY_NEWLINE);
									}else{
										vty_out(vty, "  |_cause %-27.27d :\t%lu\t%lu%s", k, plmn_stats->v2_rx[j].causes?plmn_stats->v2_rx[j].causes[k]:0, plmn_stats->v2_tx[j].causes?plmn_stats->v2_tx[j].causes[k]:0, VTY_NEWLINE);
									}
								}
							}
						}
					}
					for (int k = 0; k < STATS_GTP_SIZE; k++) {
						if(plmn_stats->v1_rx[0].causes)
							FREE(plmn_stats->v1_rx[0].causes);
						if(plmn_stats->v1_tx[0].causes)
							FREE(plmn_stats->v1_tx[0].causes);
						if(plmn_stats->v2_rx[0].causes)
							FREE(plmn_stats->v2_rx[0].causes);
						if(plmn_stats->v2_tx[0].causes)
							FREE(plmn_stats->v2_tx[0].causes);
					}
					gtp_htab_destroy(plmn_stats->peers);
					FREE(plmn_stats->peers);
					FREE(plmn_stats->plmn);
					FREE(plmn_stats);
				}
			}
		}
	}

	if(plmn){
		gtp_htab_destroy(tmp_ips);
		FREE(tmp_ips);
	}else{
		gtp_htab_destroy(tmp_plmns);
		FREE(tmp_plmns);
	}


	for(int j=0; j < STATS_GTP_SIZE; j++){
		if(stats_v1_rx[j].causes){
			FREE(stats_v1_rx[j].causes);
		}
		if(stats_v1_tx[j].causes){
			FREE(stats_v1_tx[j].causes);
		}
		if(stats_v2_rx[j].causes){
			FREE(stats_v2_rx[j].causes);
		}
		if(stats_v2_tx[j].causes){
			FREE(stats_v2_tx[j].causes);
		}


	}

	return 0;
}

void __gtp_sum_array(uint64_t sum[], uint64_t src[], uint8_t length){
	for(int i=0; i<length; i++){
		sum[i] += src[i];
	}
}

void __gtp_stats_show_sessions_server(gtp_server_t *srv, uint8_t *plmn, gtp_htab_t *tmp_plmns, gtp_htab_t *tmp_ips, uint64_t *sessions_by_type, uint64_t *sessions_by_rattype){
	gtp_server_worker_t *worker, *w_tmp;
	gtp_plmn_stats_t *plmn_stats;
	gtp_ip_stats_t *ip_stats;
	gtp_plmn_stats_t *tmp_plmn_stats;
	gtp_ip_stats_t *tmp_ip_stats;
	struct hlist_node *n, *hl_tmp;




	list_for_each_entry_safe(worker, w_tmp, &srv->workers, next){
		if(plmn){
			struct hlist_head *plmn_stats_head;
			plmn_stats_head = gtp_stats_plmn_hashkey(worker->stats.signalling_gtp->plmns, plmn);

			hlist_for_each_entry_safe(plmn_stats, hl_tmp, n, plmn_stats_head, hlist){
				if(memcmp(plmn_stats->plmn, plmn, GTP_PLMN_MAX_LEN)){
					continue;
				}
				__gtp_sum_array(sessions_by_type, plmn_stats->sessions_by_type, SESSIONTYPE_ENUM_SIZE);
				__gtp_sum_array(sessions_by_rattype, plmn_stats->sessions_by_rattype, RATTYPE_ENUM_SIZE);

				for (int i = 0; i < STATS_GTP_IP_HASHTAB_SIZE; i++) {
					hlist_for_each_entry_safe(ip_stats, hl_tmp, n, &plmn_stats->peers->htab[i], hlist){
						tmp_ip_stats = __gtp_stats_ip_hash(tmp_ips, ip_stats->ip);
						__gtp_sum_array(tmp_ip_stats->sessions_by_type, ip_stats->sessions_by_type, SESSIONTYPE_ENUM_SIZE);
						__gtp_sum_array(tmp_ip_stats->sessions_by_rattype, ip_stats->sessions_by_rattype, RATTYPE_ENUM_SIZE);
					}
				}
			}
		}else{
			__gtp_sum_array(sessions_by_type, worker->stats.signalling_gtp->sessions_by_type, SESSIONTYPE_ENUM_SIZE);
			__gtp_sum_array(sessions_by_rattype, worker->stats.signalling_gtp->sessions_by_rattype, RATTYPE_ENUM_SIZE);
			for (int i = 0; i < STATS_GTP_PLMN_HASHTAB_SIZE; i++) {
				hlist_for_each_entry_safe(plmn_stats, hl_tmp, n, &worker->stats.signalling_gtp->plmns->htab[i], hlist){
					tmp_plmn_stats = __gtp_stats_plmn_hash(tmp_plmns, plmn_stats->plmn);
					__gtp_sum_array(tmp_plmn_stats->sessions_by_type, plmn_stats->sessions_by_type, SESSIONTYPE_ENUM_SIZE);
					__gtp_sum_array(tmp_plmn_stats->sessions_by_rattype, plmn_stats->sessions_by_rattype, RATTYPE_ENUM_SIZE);
				}
			}
		}
	}
}


static int
gtp_stats_sessions_show(vty_t *vty, uint8_t *plmn)
{
	const list_head_t *l = &daemon_data->gtp_switch_ctx;
	gtp_switch_t *ctx;
	gtp_plmn_stats_t *plmn_stats;
	gtp_ip_stats_t *ip_stats;
	struct hlist_node *n;
	struct hlist_node *hl_tmp;
	gtp_htab_t *tmp_plmns = NULL;
	gtp_htab_t *tmp_ips = NULL;
	uint8_t unknown_plmn[GTP_PLMN_MAX_LEN] = {0};

	uint64_t sessions_by_type[SESSIONTYPE_ENUM_SIZE] = {0};
	uint64_t sessions_by_rattype[RATTYPE_ENUM_SIZE] = {0};

	if(plmn){
		tmp_ips = MALLOC(sizeof(struct hlist_head));
		gtp_htab_init(tmp_ips, STATS_GTP_IP_HASHTAB_SIZE);
	}else{
		tmp_plmns = MALLOC(sizeof(struct hlist_head));
		gtp_htab_init(tmp_plmns, STATS_GTP_PLMN_HASHTAB_SIZE);
	}

	list_for_each_entry(ctx, l, next) {
		__gtp_stats_show_sessions_server(&ctx->gtpc, plmn, tmp_plmns, tmp_ips, sessions_by_type, sessions_by_rattype);
		if (__test_bit(GTP_FL_CTL_BIT, &ctx->gtpc_egress.flags)) {
			__gtp_stats_show_sessions_server(&ctx->gtpc_egress, plmn, tmp_plmns, tmp_ips, sessions_by_type, sessions_by_rattype);
		}
		if(plmn){
			vty_out(vty, "\t\t\tnumber%s", VTY_NEWLINE);

			for(int j=0; j < SESSIONTYPE_ENUM_SIZE; j++){
				if(sessions_by_type[j] > 0){
					vty_out(vty, "%s :\t\t%lu%s", gtp_session_type2str[j].name, sessions_by_type[j], VTY_NEWLINE);
				}
			}
			for(int j=0; j < RATTYPE_ENUM_SIZE; j++){
				if(sessions_by_rattype[j] > 0){
					vty_out(vty, "%s :\t\t%lu%s", gtp_session_rattype2str[j].name, sessions_by_rattype[j], VTY_NEWLINE);
				}
			}

			for (int i = 0; i < STATS_GTP_IP_HASHTAB_SIZE; i++) {
				hlist_for_each_entry_safe(ip_stats, hl_tmp, n, &tmp_ips->htab[i], hlist){
					vty_out(vty, "IP %u.%u.%u.%u%s", NIPQUAD(((struct sockaddr_in *)ip_stats->ip)->sin_addr), VTY_NEWLINE);
					for(int j=0; j < SESSIONTYPE_ENUM_SIZE; j++){
						if(ip_stats->sessions_by_type[j] > 0){
							vty_out(vty, "  %s :\t\t%lu%s", gtp_session_type2str[j].name, ip_stats->sessions_by_type[j], VTY_NEWLINE);
						}
					}
					for(int j=0; j < RATTYPE_ENUM_SIZE; j++){
						if(ip_stats->sessions_by_rattype[j] > 0){
							vty_out(vty, "  %s :\t\t%lu%s", gtp_session_rattype2str[j].name, ip_stats->sessions_by_rattype[j], VTY_NEWLINE);
						}
					}

				}
			}
			gtp_htab_destroy(tmp_ips);
			FREE(tmp_ips);
		}else{
			vty_out(vty, "\t\t\tnumber%s", VTY_NEWLINE);
			for(int j=0; j < SESSIONTYPE_ENUM_SIZE; j++){
				if(sessions_by_type[j] > 0){
					vty_out(vty, "%s :\t\t%lu%s", gtp_session_type2str[j].name, sessions_by_type[j], VTY_NEWLINE);
				}
			}
			for(int j=0; j < RATTYPE_ENUM_SIZE; j++){
				if(sessions_by_rattype[j] > 0){
					vty_out(vty, "%s :\t\t%lu%s", gtp_session_rattype2str[j].name, sessions_by_rattype[j], VTY_NEWLINE);
				}
			}
			for (int i = 0; i < STATS_GTP_PLMN_HASHTAB_SIZE; i++) {
				hlist_for_each_entry_safe(plmn_stats, hl_tmp, n, &tmp_plmns->htab[i], hlist){
					if(!memcmp(plmn_stats->plmn, unknown_plmn, GTP_PLMN_MAX_LEN)){
						vty_out(vty, "PLMN UNKNOWN%s", VTY_NEWLINE);
					}else{
						char splmn_s[7];
						plmn_bcd_to_string(plmn_stats->plmn, splmn_s);
						vty_out(vty, "PLMN %s%s", splmn_s, VTY_NEWLINE);
					}
					for(int j=0; j < SESSIONTYPE_ENUM_SIZE; j++){
						if(plmn_stats->sessions_by_type[j] > 0){
							vty_out(vty, "  %s :\t\t%lu%s", gtp_session_type2str[j].name, plmn_stats->sessions_by_type[j], VTY_NEWLINE);
						}
					}
					for(int j=0; j < RATTYPE_ENUM_SIZE; j++){
						if(plmn_stats->sessions_by_rattype[j] > 0){
							vty_out(vty, "  %s :\t\t%lu%s", gtp_session_rattype2str[j].name, plmn_stats->sessions_by_rattype[j], VTY_NEWLINE);
						}
					}

				}
			}
			gtp_htab_destroy(tmp_plmns);
			FREE(tmp_plmns);
		}
	}

	return 0;
}

/* Show */
DEFUN(show_stats_gtpc,
      show_stats_gtpc_cmd,
      "show stats gtpc [PLMN]",
      SHOW_STR
      "Show GTPc statistics by plmn\n")
{
	if (argc >= 1) {
		uint8_t *plmn = MALLOC(GTP_PLMN_MAX_LEN);
		plmn_string_to_bcd(argv[0], plmn);
		gtp_stats_gtp_show(vty, plmn);
		FREE(plmn);
	}else{
		gtp_stats_gtp_show(vty, NULL);
	}

	return CMD_SUCCESS;
}

DEFUN(show_stats_sessions,
	show_stats_sessions_cmd,
	"show stats sessions [PLMN]",
	SHOW_STR
	"Show number of sessions by plmn\n")
  {
	  if (argc >= 1) {
		  uint8_t *plmn = MALLOC(GTP_PLMN_MAX_LEN);
		  plmn_string_to_bcd(argv[0], plmn);
		  gtp_stats_sessions_show(vty, plmn);
		  FREE(plmn);
	  }else{
		  gtp_stats_sessions_show(vty, NULL);
	  }
  
	  return CMD_SUCCESS;
  }
  


/*
 *	VTY init
 */
int
gtp_stats_vty_init(void)
{

	/* Install PDN commands. */
	install_node(&stats_node);


	/* Install show commands */
	install_element(VIEW_NODE, &show_stats_gtpc_cmd);
	install_element(ENABLE_NODE, &show_stats_gtpc_cmd);
	install_element(VIEW_NODE, &show_stats_sessions_cmd);
	install_element(ENABLE_NODE, &show_stats_sessions_cmd);


	return 0;
}
