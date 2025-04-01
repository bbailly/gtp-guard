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

static struct hlist_head *
gtp_stats_plmn_hashkey(gtp_htab_t *h, plmn_t plmn)
{
	/* TODO maybe to compare using one 32 bits word and not 3 8 bits words */
	return h->htab + (jhash_3words(plmn[0],plmn[1],plmn[2], 0) & STATS_GTP_PLMN_HASHTAB_MASK);
}

static struct hlist_head *
gtp_stats_ip_hashkey(gtp_htab_t *h, struct sockaddr *ip)
{
	if(ip->sa_family == AF_INET){
		return h->htab + (jhash_1word(((struct sockaddr_in*)ip)->sin_addr.s_addr, 0) & STATS_GTP_IP_HASHTAB_MASK);
	}else if (ip->sa_family == AF_INET6){
		return h->htab + (jhash2(((struct sockaddr_in6*)ip)->sin6_addr.__in6_u.__u6_addr32, 16, 0) & STATS_GTP_IP_HASHTAB_MASK);
	} else {
		return NULL;
	}
	
}


 gtp_ip_stats_t *
 __gtp_stats_ip_hash(gtp_htab_t *h, struct sockaddr ip)
 {
	 struct hlist_head *ip_stats_head;
	 gtp_ip_stats_t *ip_stats;
	 ip_stats_head = gtp_stats_ip_hashkey(h, ip);
 
	 struct hlist_node *n;
	 hlist_for_each_entry(ip_stats, n, ip_stats_head, hlist){
		if(ip.sa_family == ip.sa_family){
			if(!memcmp(ip_stats->ip.sa_data, ip.sa_data, sizeof(struct sockaddr))){
				log_message(LOG_DEBUG, "%s(): IP 0x%x already present"
					, __FUNCTION__
					, ip.sa_data);	
				return ip_stats;
			}
		}
	 }
	log_message(LOG_DEBUG, "%s(): IP %s not present adding it"
		, __FUNCTION__
		, ip.sa_data);
		ip_stats = MALLOC(sizeof(gtp_plmn_stats_t));
	ip_stats->ip.sa_family = ip.sa_family;
	memcpy(ip_stats->ip.sa_data, ip.sa_data, sizeof(struct sockaddr));
	hlist_add_head(&ip_stats->hlist, ip_stats_head);
	return ip_stats;
 }
 
 gtp_plmn_stats_t *
__gtp_stats_plmn_hash(gtp_htab_t *h, plmn_t plmn)
{
	struct hlist_head *plmn_stats_head;
	gtp_plmn_stats_t *plmn_stats;
	plmn_stats_head = gtp_stats_plmn_hashkey(h, plmn);

	struct hlist_node *n;
	char splmn_s[7];
	plmn_bcd_to_string(plmn, splmn_s);	
	hlist_for_each_entry(plmn_stats, n, plmn_stats_head, hlist){	
		if(!memcmp(plmn_stats->plmn, plmn, sizeof(plmn_t))){
			log_message(LOG_DEBUG, "%s(): PLMN %s already present"
				, __FUNCTION__
				, splmn_s);		
			return plmn_stats;
		}
	}
	log_message(LOG_DEBUG, "%s(): PLMN %s not present adding it"
		, __FUNCTION__
		, splmn_s);		
	plmn_stats = MALLOC(sizeof(gtp_plmn_stats_t));
	memcpy(plmn_stats->plmn, plmn, sizeof(plmn_t));
	gtp_htab_init(plmn_stats->peers, STATS_GTP_IP_HASHTAB_SIZE);
	hlist_add_head(&plmn_stats->hlist, plmn_stats_head);
	return plmn_stats;
}

int gtp_stats_gtp_signalling_inc(gtp_server_stats_t server_stats, plmn_t peer_plmn, struct sockaddr_storage *peer_ip, protocol_t protocol, direction_t direction, uint8_t message_type, uint8_t cause){
	gtp_plmn_stats_t *plmn_stats = NULL;
	uint32_t plmn_hash = 0;
	memcpy(&plmn_hash, peer_plmn, sizeof(plmn_t));
	dlock_lock_id(server_stats.signalling_gtp->plmns->dlock, plmn_hash, 0);
	plmn_stats = __gtp_stats_plmn_hash(server_stats.signalling_gtp->plmns, peer_plmn);

	if(protocol == proto_gtpv1){
		if(direction == dir_rx){
			server_stats.signalling_gtp->v1_rx[message_type].count++;
			plmn_stats->v1_rx[message_type].count++;
		}else{
			server_stats.signalling_gtp->v1_tx[message_type].count++;
			plmn_stats->v1_tx[message_type].count++;
		}
	}else if(protocol == proto_gtpv2){
		if(direction == dir_rx){
			server_stats.signalling_gtp->v2_rx[message_type].count++;
			plmn_stats->v2_rx[message_type].count++;
		}else{
			server_stats.signalling_gtp->v2_tx[message_type].count++;
			plmn_stats->v2_tx[message_type].count++;
		}

	}else{
		dlock_unlock_id(server_stats.signalling_gtp->plmns->dlock, plmn_hash, 0);
		log_message(LOG_DEBUG, "%s(): unexpected protocol %d"
			, __FUNCTION__
			, protocol);
		return -1;
	}
	dlock_unlock_id(server_stats.signalling_gtp->plmns->dlock, plmn_hash, 0);
	char splmn_s[7];
	plmn_bcd_to_string(peer_plmn, splmn_s);	
	log_message(LOG_DEBUG, "%s(): increment counter for PLMN %s, protocol %d, direction %d, message_type %hhu, cause %hhu"
		, __FUNCTION__
		, splmn_s, protocol, direction, message_type, cause);
	return 0;
}

cmd_node_t stats_node = {
	.node = STATS_NODE,
	.parent_node = ENABLE_NODE,
	.prompt = "%s# ",
};
extern data_t *daemon_data;

void __gtp_sum_stats(gtp_stats_t dst[], gtp_stats_t src[], int length){
	for(int i=0; i<length; i++){
		dst[i].count += src[i].count;
		dst[i].unsupported += src[i].unsupported;
	}
}

static int
gtp_stats_show(vty_t *vty, plmn_t plmn)
{
	const list_head_t *l = &daemon_data->gtp_switch_ctx;
	gtp_switch_t *ctx;
	gtp_server_t *srv;
	gtp_server_worker_t *worker, *w_tmp;
	gtp_plmn_stats_t *plmn_stats;
	struct hlist_node *n;
	struct hlist_node *hl_tmp;

	gtp_stats_t stats_v1_rx[0xff] = {0};
	gtp_stats_t stats_v1_tx[0xff] = {0};
	gtp_stats_t stats_v2_rx[0xff] = {0};
	gtp_stats_t stats_v2_tx[0xff] = {0};

	list_for_each_entry(ctx, l, next) {
		srv = &ctx->gtpc;
		list_for_each_entry_safe(worker, w_tmp, &srv->workers, next){
			if(!plmn){
				vty_out(vty, "Worker %d%s", worker->id, VTY_NEWLINE);
				vty_out(vty, "  create-session requests : %lu%s", worker->stats.signalling_gtp->v2_rx[GTP2C_CREATE_SESSION_REQUEST_TYPE].count, VTY_NEWLINE);
				for (int i = 0; i < STATS_GTP_PLMN_HASHTAB_SIZE; i++) {
					hlist_for_each_entry_safe(plmn_stats, hl_tmp, n, &worker->stats.signalling_gtp->plmns->htab[i], hlist){
						char splmn_s[7];
						plmn_bcd_to_string(plmn_stats->plmn, splmn_s);
						vty_out(vty, "  Statistics for PLMN %s (0x%02hhx%02hhx%02hhx)%s", splmn_s, plmn_stats->plmn[0], plmn_stats->plmn[1], plmn_stats->plmn[2], VTY_NEWLINE);
						vty_out(vty, "    create-session requests : %lu%s", plmn_stats->v2_rx[GTP2C_CREATE_SESSION_REQUEST_TYPE].count, VTY_NEWLINE);
					}
				}
			}else{
				struct hlist_head *plmn_stats_head;
				plmn_stats_head = gtp_stats_plmn_hashkey(worker->stats.signalling_gtp->plmns, plmn);

				hlist_for_each_entry_safe(plmn_stats, hl_tmp, n, plmn_stats_head, hlist){
					if(memcmp(plmn_stats->plmn, plmn, sizeof(plmn_t))){
						continue;
					}
					log_message(LOG_DEBUG, "%s(): matched plmn for worker %d, create-session requests %lu"
						, __FUNCTION__
						,worker->id, plmn_stats->v2_rx[GTP2C_CREATE_SESSION_REQUEST_TYPE].count);

					__gtp_sum_stats(stats_v1_rx, plmn_stats->v1_rx, 0xff);
					__gtp_sum_stats(stats_v1_tx, plmn_stats->v1_tx, 0xff);
					__gtp_sum_stats(stats_v2_rx, plmn_stats->v2_rx, 0xff);
					__gtp_sum_stats(stats_v2_tx, plmn_stats->v2_tx, 0xff);
				}

			}
		}
		if(plmn){
			char splmn_s[7];
			plmn_bcd_to_string(plmn, splmn_s);
			vty_out(vty, "PLMN %s%s", splmn_s, VTY_NEWLINE);
			vty_out(vty, "  create-session requests : %lu%s", stats_v2_rx[GTP2C_CREATE_SESSION_REQUEST_TYPE].count, VTY_NEWLINE);

		}
	}



	return 0;
}


/* Show */
DEFUN(show_stats_plmn,
      show_stats_plmn_cmd,
      "show stats [PLMN]",
      SHOW_STR
      "Show statistics by plmn\n")
{
	if (argc >= 1) {
		plmn_t plmn;
		plmn_string_to_bcd(argv[0], plmn);
		log_message(LOG_DEBUG, "%s(): show statistics for PLMN %s (0x%02hhx%02hhx%02hhx)"
			, __FUNCTION__
			, argv[0], plmn[0], plmn[1], plmn[2]);	
		gtp_stats_show(vty, plmn);
	}else{
		gtp_stats_show(vty, NULL);
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
	install_element(VIEW_NODE, &show_stats_plmn_cmd);
	install_element(ENABLE_NODE, &show_stats_plmn_cmd);

	return 0;
}
