#ifndef _GTP_STATS_H
#define _GTP_STATS_H

/* PLMN Hash table */
#define STATS_GTP_PLMN_HASHTAB_BITS  20
#define STATS_GTP_PLMN_HASHTAB_SIZE  (1 << STATS_GTP_PLMN_HASHTAB_BITS)
#define STATS_GTP_PLMN_HASHTAB_MASK  (STATS_GTP_PLMN_HASHTAB_SIZE - 1)

/* IP Hash table */
#define STATS_GTP_IP_HASHTAB_BITS  10
#define STATS_GTP_IP_HASHTAB_SIZE  (1 << STATS_GTP_IP_HASHTAB_BITS)
#define STATS_GTP_IP_HASHTAB_MASK  (STATS_GTP_IP_HASHTAB_SIZE - 1)

typedef enum _metric_type {
	signalling,
	userplan,
	sessions
} metric_type_t;

typedef enum _protocol {
	proto_gtpv1,
	proto_gtpv2,
	proto_gtpu,
	proto_pppoe,
	proto_dns
} protocol_t;

typedef enum _direction {
	dir_rx,
	dir_tx
} direction_t;

typedef enum _session_type {
	sessiontype_gtpp_to_sgw,
	sessiontype_gtpp_to_pgw,
	sessiontype_pgw,
	sessiontype_pppoe,
	sessiontype_gtp_guard
} session_type_t;


typedef struct _gtp_stats {
	uint64_t		count;
	uint64_t		unsupported;
} gtp_stats_t;


typedef struct _gtp_ip_stats {
	struct sockaddr		ip;
	gtp_stats_t		v1_rx[0xff]; /* GTPv1 RX stats */
	gtp_stats_t		v1_tx[0xff]; /* GTPv1 TX stats */
	gtp_stats_t		v2_rx[0xff]; /* GTPv2 RX stats */
	gtp_stats_t		v2_tx[0xff]; /* GTPv2 TX stats */
	struct hlist_node       hlist;
} gtp_ip_stats_t;


typedef struct _gtp_plmn_stats {
	plmn_t			plmn;
	gtp_htab_t		*peers;
	gtp_stats_t		v1_rx[0xff]; /* GTPv1 RX stats */
	gtp_stats_t		v1_tx[0xff]; /* GTPv1 TX stats */
	gtp_stats_t		v2_rx[0xff]; /* GTPv2 RX stats */
	gtp_stats_t		v2_tx[0xff]; /* GTPv2 TX stats */
	struct hlist_node       hlist;
} gtp_plmn_stats_t;

typedef struct _gtp_signalling_gtp_stats {
	gtp_htab_t		*plmns;
	gtp_stats_t		v1_rx[0xff]; /* GTPv1 RX stats */
	gtp_stats_t		v1_tx[0xff]; /* GTPv1 TX stats */
	gtp_stats_t		v2_rx[0xff]; /* GTPv2 RX stats */
	gtp_stats_t		v2_tx[0xff]; /* GTPv2 TX stats */
} gtp_signalling_gtp_stats_t;

typedef struct _gtp_pppoe_instance_stats {
	char			*name;
	gtp_stats_t		rx[0xff]; /* PPPoE RX stats */
	gtp_stats_t		tx[0xff]; /* PPPoE RX stats */
	struct hlist_node       hlist;
} gtp_pppoe_instance_stats_t;


typedef struct _gtp_signalling_pppoe_stats {
	gtp_htab_t		*instances;
	gtp_stats_t		rx[0xff];
	gtp_stats_t		tx[0xff];
} gtp_signalling_pppoe_stats_t;


/* Statistics counters */

typedef struct _gtp_server_stats {
	gtp_signalling_gtp_stats_t	*signalling_gtp;
	gtp_signalling_pppoe_stats_t	*signalling_pppoe;
} gtp_server_stats_t;


/* Prototypes */

extern int gtp_stats_vty_init(void);

/* PLMN, IP, gtp version, direction, message type, cause */
extern int gtp_stats_gtp_signalling_inc(gtp_server_stats_t, plmn_t, struct sockaddr_storage *, protocol_t, direction_t, uint8_t, uint8_t);

#endif
