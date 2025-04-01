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
 * Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

/* local includes */
#include "gtp_guard.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	GTPv1 utilities
 */
static const struct {
	size_t		len;
} gtp1_ie_len[128] = {
	[1]	=	{1},
	[2]	=	{8},
	[3]	=	{6},
	[4]	=	{4},
	[5]	=	{4},
	[8]	=	{1},
	[9]	=	{28},
	[11]	=	{1},
	[12]	=	{3},
	[13]	=	{1},
	[14]	=	{1},
	[15]	=	{1},
	[16]	=	{4},
	[17]	=	{4},
	[18]	=	{5},
	[19]	=	{1},
	[20]	=	{1},
	[21]	=	{1},
	[22]	=	{9},
	[23]	=	{1},
	[24]	=	{1},
	[25]	=	{2},
	[26]	=	{2},
	[27]	=	{2},
	[28]	=	{2},
	[29]	=	{1},
	[127]	=	{4},
};


size_t
gtp1_get_header_len(gtp1_hdr_t *h)
{
	if ((h->flags & 0x07) == 0)
		return GTP1C_HEADER_LEN_SHORT;

	return GTP1C_HEADER_LEN_LONG;
}

uint8_t *
gtp1_get_ie_offset(uint8_t type, uint8_t *buffer, uint8_t *end)
{
	size_t offset = 0;
	uint8_t *cp;
	gtp1_ie_t *ie;

	for (cp = buffer; cp < end; cp += offset) {
		if (*cp == type)
			return cp;
		if (*cp < 0x80) {
			offset = gtp1_ie_len[*cp].len + 1;
			continue;
		}
		ie = (gtp1_ie_t *) cp;
		offset = sizeof(gtp1_ie_t) + ntohs(ie->length);
	}

	return NULL;
}

uint8_t *
gtp1_get_ie(uint8_t type, pkt_buffer_t *pbuff)
{
	gtp1_hdr_t *h = (gtp1_hdr_t *) pbuff->head;
	size_t offset = gtp1_get_header_len(h);

	return gtp1_get_ie_offset(type, pbuff->head+offset, pbuff->end);
}

size_t
gtp1_ie_add_tail(pkt_buffer_t *pbuff, uint16_t ie_length)
{
	if (pkt_buffer_put_zero(pbuff, ie_length) < 0)
		return 0;

	return ie_length;
}

int
gtp1_ie_apn_extract(gtp1_ie_apn_t *apn, char *buffer, size_t size)
{
	uint8_t *cp, *end = apn->apn+ntohs(apn->h.length);
	size_t offset = 0;

	for (cp = apn->apn; cp < end; cp+=*cp+1) {
		if (offset + *cp > size)
			return -1;
		memcpy(buffer+offset, cp+1, *cp);
		offset += *cp;
		buffer[offset++] = '.';
	}

	buffer[offset - 1] = 0;

	return 0;
}


/*
 *	GTPv2 utilities
 */

int plmn_string_to_bcd(const char* plmn_s, uint8_t * plmn){
	if(strlen(plmn_s) < 5 || strlen(plmn_s) > 6){
		return -1;
	}
	uint32_t plmn_i = strtol(plmn_s,NULL,16);

	if(strlen(plmn_s) == 5){
		plmn[0] = ((plmn_i & 0xf0000) >> 16) + ((plmn_i & 0x0f000) >> 8);
		plmn[1] = ((plmn_i & 0x00f00) >> 8) + 0xf0;
		plmn[2] = ((plmn_i & 0x000f0) >> 4) + ((plmn_i & 0x0000f) << 4);
	}else{
		plmn[0] = ((plmn_i & 0xf00000) >> 20) + ((plmn_i & 0x0f0000) >> 12);
		plmn[1] = ((plmn_i & 0x00f000) >> 12) + ((plmn_i & 0x000f00) >> 4);
		plmn[2] = ((plmn_i & 0x0000f0) >> 4) + ((plmn_i & 0x00000f) << 4);

	}
	return 0;
}

int plmn_bcd_to_string(const uint8_t * plmn, char * plmn_s){
	if(!((plmn[0] & 0xf0) > 0x90 || (plmn[0] & 0x0f) > 0x09 || (plmn[1] & 0x0f) > 0x09 || (plmn[2] & 0xf0) > 0x90 || (plmn[2] & 0x0f) > 0x09) && (plmn[1] & 0xf0) == 0xf0){
		return sprintf(plmn_s, "%x%x%x%x%x", plmn[0] & 0x0f, (plmn[0] & 0xf0) >> 4, plmn[1] & 0x0f, plmn[2] & 0x0f, (plmn[2] & 0xf0) >> 4);
	}
	return sprintf(plmn_s, "%x%x%x%x%x%x", plmn[0] & 0x0f, (plmn[0] & 0xf0) >> 4, plmn[1] & 0x0f, (plmn[1] & 0xf0) >> 4, plmn[2] & 0x0f, (plmn[2] & 0xf0) >> 4);
}

int
bcd_buffer_swap(uint8_t *buffer_in, int size, uint8_t *buffer_out)
{
	int i, high, low;

	for (i = 0; i < size; i++) {
		high = buffer_in[i] << 4;
		low = buffer_in[i] >> 4;
		buffer_out[i] = high | low;
		if (high == 0xf || low == 0xf)
			return i+1;
	}

	return size;
}

int
str_imsi_to_bcd_swap(char *buffer_in, size_t size, uint8_t *buffer_out)
{
	stringtohex(buffer_in, size, (char *)buffer_out, 8);
	buffer_out[7] |= 0x0f;
	return swapbuffer(buffer_out, 8, buffer_out);
}

int64_t
bcd_to_int64(const uint8_t *buffer, size_t size)
{
	int64_t value = 0;
	uint8_t high, low;
	int i;

	/* With bit swapping */
	for (i = 0; i < size; i++) {
		low = (buffer[i] & 0xf0) >> 4;
		high = buffer[i] & 0x0f;
		if (high > 9)
			return value;
		value = (value * 10) + high;

		if (low > 9)
			return value;
		value = (value * 10) + low;
	}

	return value;
}

int
int64_to_bcd_swap(const uint64_t value, uint8_t *buffer, size_t size)
{
	int len = 0, i;
	uint64_t v;
	uint8_t tmp;

	/* math would provide it simply with Log:
	 * [floor(log10(value)) + 1] but iterative approach on integer
	 * is best... At least with Intel FPU (sound weird...) */
	for (v = value; v; v/=10) {
		if (++len > size*2)
			return -1;
	}

	if (!!(len % 2))
		buffer[len / 2] = 0xf0;

	for (i = len-1, v=value; i >= 0; i--, v/=10) {
		tmp = (uint8_t) (v % 10);
		buffer[i / 2] |= !!(i % 2) ? tmp << 4 : tmp;
	}

	return 0;
}

int
int64_to_bcd(const uint64_t value, uint8_t *buffer, size_t size)
{
	int len = 0, i;
	uint64_t v;
	uint8_t tmp;

	/* math would provide it simply with Log:
	 * [floor(log10(value)) + 1] but iterative approach on integer
	 * is best... At least with Intel FPU (sound weird...) */
	for (v = value; v; v/=10) {
		if (++len > size*2) {
			len -= 2;
			break;
		}
	}

	for (i = len, v=value; i >= 0; i--, v/=10) {
		tmp = (uint8_t) (v % 10);
		buffer[i / 2] |= !!(i % 2) ? tmp : tmp << 4;
	}

	return 0;
}

/* PLMN Related */
int
str_plmn_to_bcd(const char *src, uint8_t *dst, size_t dsize)
{
	static char digits[] = "0123456789";
	int str_len = strlen(src);
	const char *end = src + str_len, *cp, *pch;
	char tmp;
	int i = 0;

	/* Never more than 6 digits */
	if (str_len > 6)
		return -1;

	if (str_len / 2 > dsize)
		return -1;
	memset(dst, 0, dsize);

	for (cp = src; cp < end; cp++) {
		pch = strchr(digits, tolower((int) *cp));
		if (!pch)
			return -1;

		tmp = (uint8_t) (pch - digits) << 4 * !!(i % 2);

		/* MNC can be 2 or 3 digits. In that last
		 * case, last digit of MNC replace 'f' in
		 * BCD buffer output... */
		if (i == 6) {
			dst[1] = (tmp << 4) | (dst[1] & 0x0f);
			break;
		}

		dst[i / 2] |= tmp;

		/* MCC is always 3 digits */
		if (++i == 3)
			dst[i++ / 2] |= 0xf0;
	}

	return 0;
}

int64_t
bcd_plmn_to_int64(const uint8_t *src, size_t ssize)
{
	int64_t plmn = 0;
	int i;

	if (ssize != 3)
		return -1;

	for (i = 0; i < ssize; i++) {
		plmn = 10 * plmn + (src[i] & 0x0f);
		if ((src[i] >> 4) != 0xf)
			plmn = 10 * plmn + (src[i] >> 4);
	}

	/* Last digit of MNC */
	if ((src[1] >> 4) != 0xf)
		plmn = 10 * plmn + (src[1] >> 4);

	return plmn;
}

int
bcd_plmn_cmp(const uint8_t *a, const uint8_t *b)
{
	int i;

	for (i = 0; i < 3; i++) {
		if (a[i] ^ b[i])
			return -1;
	}

	return 0;
}

bool
bcd_imsi_plmn_match(const uint8_t *imsi, const uint8_t *plmn)
{
	uint8_t tmp;

	/* a bit manual to keep it readable... */

	/* MCC matching */
	if (imsi[0] ^ plmn[0])
		return false;

	if ((imsi[1] ^ plmn[1]) & 0x0f)
		return false;

	/* MNC matching */
	tmp = (imsi[1] >> 4) | (imsi[2] << 4);
	if (plmn[2] ^ tmp)
		return false;

	/* MNC is 3 digits ? */
	if ((plmn[1] >> 4) != 0xf) {
		if ((imsi[2] >> 4) ^ (plmn[1] >> 4))
			return false;
	}

	return true;
}

/* IMSI related */
int
gtp_imsi_ether_addr_build(const uint64_t imsi, struct ether_addr *eth, uint8_t id)
{
	uint8_t eui_oui[8] = { 0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f };

	int64_to_bcd(imsi, eth->ether_addr_octet, ETH_ALEN);

	/* RFC5342.2.1: Set Local bit of EUI-48 */
	eth->ether_addr_octet[0] = (id < 8) ? eui_oui[id] : 0;
	return 0;
}

int
gtp_ifid_from_ether_build(struct ether_addr *eth, struct in6_addr *ifid)
{
	int i, j;

	/* RFC5072.4.1 section 1) : Add 0xFF & 0xFE in the middle of EUI-48 */
	for (i = 0, j = 0; i < 8; i++) {
		if (i == 3) {
			ifid->s6_addr[i+++8] = 0xFF;
			ifid->s6_addr[i+8] = 0xFE;
			continue;
		}

		ifid->s6_addr[i+8] = eth->ether_addr_octet[j++];
	}

	return 0;
}

int
gtp_imsi_rewrite(gtp_apn_t *apn, uint8_t *imsi)
{
	list_head_t *l = &apn->imsi_match;
	gtp_rewrite_rule_t *rule, *rule_match = NULL;
	int len;

	/* FIXME: this list MUST be protected or use lock-less */
	if (list_empty(l))
		return -1;

	list_for_each_entry(rule, l, next) {
		if (memcmp(rule->match, imsi, rule->match_len / 2) == 0) {
			if (!!(rule->match_len % 2)) {
				if ((imsi[rule->match_len / 2] & 0x0f) == (rule->match[rule->match_len / 2] & 0x0f)) {
					rule_match = rule;
					break;
				}
			} else {
				rule_match = rule;
				break;
			}
		}
	}

	if (!rule_match)
		return -1;

	/* Properly rewrite */
	len = rule_match->rewrite_len;
	memcpy(imsi, rule_match->rewrite, len / 2);
	if (!!(len % 2)) {
		imsi[len / 2] = (imsi[len / 2] & 0xf0) | (rule_match->rewrite[len / 2] & 0x0f);
	}

	return 0;
}

int
gtp_ie_imsi_rewrite(gtp_apn_t *apn, uint8_t *buffer)
{
	gtp_ie_imsi_t *ie_imsi = (gtp_ie_imsi_t *) buffer;

	return gtp_imsi_rewrite(apn, ie_imsi->imsi);
}

/* APN related */
int
gtp_apn_extract_ni(char *apn, size_t apn_size, char *buffer, size_t size)
{
	char *cp, *end = apn+apn_size;
	int labels_cnt = 0;

	if (!apn_size)
		return -1;

	for (cp = end; cp != apn && labels_cnt < 3; cp--) {
		if (*cp == '.')
			labels_cnt++;
	}

	memcpy(buffer, apn, cp - apn + 1);
	return 0;
}

int
gtp_ie_apn_labels_cnt(const char *buffer, size_t size)
{
	const char *end = buffer + size;
	const char *cp;
	int cnt = 0;

	for (cp = buffer; cp < end; cp+=*cp+1)
		cnt++;

	return cnt;
}

int
gtp_ie_apn_extract_ni(gtp_ie_apn_t *apn, char *buffer, size_t size)
{
	uint8_t *cp, *end = apn->apn+ntohs(apn->h.length);
	int labels_cnt = 0;
	size_t offset = 0;

	/* Phase 1 : find out labels nb */
	labels_cnt = gtp_ie_apn_labels_cnt((char *)apn->apn, ntohs(apn->h.length));

	/* Phase 2 : copy labels */
	for (cp = apn->apn; cp < end && labels_cnt-- > 3; cp+=*cp+1) {
		if (offset + *cp > size)
			return -1;

		memcpy(buffer+offset, cp+1, *cp);
		offset += *cp;
		buffer[offset++] = '.';
	}

	buffer[offset - 1] = 0;

	return 0;
}

static int
gtp_ie_apn_extract_labels(gtp_ie_apn_t *apn, int until_label, char *buffer, size_t size)
{
	uint8_t *cp, *end = apn->apn+ntohs(apn->h.length);
	int labels_cnt = 0;
	size_t offset = 0;

	/* Phase 1 : find out labels nb */
	labels_cnt = gtp_ie_apn_labels_cnt((char *)apn->apn, ntohs(apn->h.length));

	/* Phase 2 : skip NI */
	for (cp = apn->apn; cp < end && labels_cnt-- > 3; cp+=*cp+1) ;

	/* Phase 2 : copy labels */
	for (; cp < end && labels_cnt-- > until_label; cp+=*cp+1) {
		if (offset + *cp > size)
			return -1;

		memcpy(buffer+offset, cp+1, *cp);
		offset += *cp;
		buffer[offset++] = '.';
	}

	buffer[offset - 1] = 0;
	return 0;
}

int
gtp_ie_apn_extract_oi(gtp_ie_apn_t *apn, char *buffer, size_t size)
{
	return gtp_ie_apn_extract_labels(apn, -1, buffer, size);
}

int
gtp_ie_apn_extract_plmn(gtp_ie_apn_t *apn, char *buffer, size_t size)
{
	return gtp_ie_apn_extract_labels(apn, 0, buffer, size);
}

int
gtp_ie_apn_rewrite_oi(gtp_ie_apn_t *apn, size_t offset, char *buffer)
{
	uint8_t *end = apn->apn+ntohs(apn->h.length);
	uint8_t *cp = apn->apn + offset + 1;
	size_t offset_oi = 0;

	for (; cp < end; cp+=*cp+1) {
		memcpy(cp + 1, buffer + offset_oi, *cp);
		offset_oi += *cp + 1;
	}

	return 0;
}

int
gtp_ie_apn_rewrite(gtp_apn_t *apn, gtp_ie_apn_t *ie_apn, size_t offset_ni)
{
	list_head_t *l = &apn->oi_match;
	gtp_rewrite_rule_t *rule;
	char apn_oi[32];

	if (list_empty(l))
		return -1;

	memset(apn_oi, 0, 32);
	gtp_ie_apn_extract_oi(ie_apn, apn_oi, 32);

	list_for_each_entry(rule, l, next) {
		if (strncmp(rule->match, apn_oi, rule->match_len) == 0) {
			gtp_ie_apn_rewrite_oi(ie_apn, offset_ni, rule->rewrite);
			return 0;
		}
	}

	return -1;
}

int
gtp_ie_f_teid_dump(gtp_ie_f_teid_t *ie)
{
	printf(" - F-TEID\n");
	printf("  . TEID/GRE Key=0x%.4x\n", ntohl(ie->teid_grekey));
	printf("  . Interface Type=%d\n", ie->interface_type);
	if (ie->v4) {
		printf("  . IPv4=%u.%u.%u.%u\n", NIPQUAD(ie->ipv4));
	}

	return 0;
}

int
gtp_dump_ie(uint8_t *buffer, size_t size)
{
	gtp_hdr_t *h = (gtp_hdr_t *) buffer;
	uint8_t *cp, *end = buffer + size;
	size_t offset = gtp_msg_hlen(h);
	gtp_ie_t *ie;

	printf("==> Size = %ld, offset = %ld\n", size, offset);

	for (cp = buffer+offset; cp < end; cp += offset) {
		ie = (gtp_ie_t *) cp;
		printf(" * IE Type : %d (offset=%ld)\n", ie->type, offset);
		offset = sizeof(gtp_ie_t) + ntohs(ie->length);
	}

	return 0;
}

uint8_t *
gtp_get_ie_offset(uint8_t type, uint8_t *buffer, size_t size, size_t off)
{
	uint8_t *cp, *end = buffer + size;
	size_t offset = off;
	gtp_ie_t *ie;

	for (cp = buffer+offset; cp < end; cp += offset) {
		ie = (gtp_ie_t *) cp;
		if (ie->type == type)
			return cp;
		offset = sizeof(gtp_ie_t) + ntohs(ie->length);
	}

	return NULL;
}

uint8_t *
gtp_get_ie(uint8_t type, pkt_buffer_t *pbuff)
{
	gtp_hdr_t *h = (gtp_hdr_t *) pbuff->head;
	size_t offset = gtp_msg_hlen(h);

	return gtp_get_ie_offset(type, pbuff->head, pkt_buffer_len(pbuff), offset);
}

int
gtp_foreach_ie(uint8_t type, uint8_t *buffer, size_t buffer_offset, uint8_t *buffer_end,
	       gtp_server_worker_t *w, gtp_session_t *s, int direction, void *arg,
	       gtp_teid_t * (*hdl) (gtp_server_worker_t *, gtp_session_t *, int, void *, uint8_t *))
{
	size_t offset = buffer_offset;
	uint8_t *end = pkt_buffer_end(w->pbuff);
	uint8_t *cp;
	gtp_ie_t *ie;

	for (cp = buffer+offset; cp < buffer_end && cp < end; cp += offset) {
		ie = (gtp_ie_t *) cp;
		if (ie->type == type) {
			(*hdl) (w, s, direction, arg, cp);
		}

		offset = sizeof(gtp_ie_t) + ntohs(ie->length);
	}

	return 0;
}

const char* gtp_get_roaming_status_by_name(const gtp_roaming_status_t roaming_status){
	switch (roaming_status){
		case GTP_ROAMING_STATUS_HPLMN: return "HPLMN";
		case GTP_ROAMING_STATUS_ROAMING_IN: return "RIN";
		case GTP_ROAMING_STATUS_ROAMING_OUT: return "ROUT";
		default : return "Undefined";
	}
}

gtp_roaming_status_t gtp_get_roaming_status(uint8_t *imsi, uint8_t *serving_plmn, list_head_t *hplmn_list){
	/* if serving PLMN MNC is 2 digits long */
	if((serving_plmn[1] & 0xf0) == 0xf0){
		/* if the serving PLMN matches the IMSI PLMN */
		if(serving_plmn[0] == imsi[0] && (serving_plmn[1] & 0x0f) == (imsi[1] & 0x0f) && ((serving_plmn[2] & 0xf0) >> 4) == (imsi[2] & 0x0f) && (serving_plmn[2] & 0x0f) == ((imsi[1] & 0xf0) >> 4)){
			return GTP_ROAMING_STATUS_HPLMN;
		}
		gtp_plmn_t *hplmn;
		list_for_each_entry(hplmn,hplmn_list,next){
			/* if hplmn PLMN MNC is 2 digits long */
			if((hplmn->plmn[1] & 0xf0) == 0xf0){
				/* if the hplmn matches the IMSI PLMN */
				if(hplmn->plmn[0] == imsi[0] && (hplmn->plmn[1] & 0x0f) == (imsi[1] & 0x0f) && ((hplmn->plmn[2] & 0xf0) >> 4) == (imsi[2] & 0x0f) && (hplmn->plmn[2] & 0x0f) == ((imsi[1] & 0xf0) >> 4)){
					return GTP_ROAMING_STATUS_ROAMING_OUT;
				}
			}else{
				/* if the hplmn matches the IMSI PLMN */
				if(memcmp(hplmn->plmn, imsi, sizeof(hplmn->plmn))){
					return GTP_ROAMING_STATUS_ROAMING_OUT;
				}
			}
		}
		return GTP_ROAMING_STATUS_ROAMING_IN;
	}
	/* if the serving PLMN matches the IMSI PLMN */
	if(memcmp(serving_plmn, imsi, GTP_PLMN_MAX_LEN)){
		return GTP_ROAMING_STATUS_HPLMN;
	}
	gtp_plmn_t *hplmn;
	list_for_each_entry(hplmn,hplmn_list,next){
		/* if hplmn PLMN MNC is 2 digits long */
		if((hplmn->plmn[1] & 0xf0) == 0xf0){
			/* if the hplmn matches the IMSI PLMN */
			if(hplmn->plmn[0] == imsi[0] && (hplmn->plmn[1] & 0x0f) == (imsi[1] & 0x0f) && ((hplmn->plmn[2] & 0xf0) >> 4) == (imsi[2] & 0x0f) && (hplmn->plmn[2] & 0x0f) == ((imsi[1] & 0xf0) >> 4)){
				return GTP_ROAMING_STATUS_ROAMING_OUT;
			}
		}else{
			/* if the hplmn matches the IMSI PLMN */
			if(memcmp(hplmn->plmn, imsi, sizeof(hplmn->plmn))){
				return GTP_ROAMING_STATUS_ROAMING_OUT;
			}
		}
	}
	return GTP_ROAMING_STATUS_ROAMING_IN;
}

/*
 *      GTP-U related
 */
ssize_t
gtpu_get_header_len(pkt_buffer_t *buffer)
{
	ssize_t len = GTP1U_HEADER_LEN;
	gtp_hdr_t *gtph = (gtp_hdr_t *) buffer->head;
	uint8_t *ext_h = NULL;

	if (pkt_buffer_len(buffer) < len)
		return -1;

	if (gtph->flags & GTPU_FL_E) {
	        len += GTP1U_EXTENSION_HEADER_LEN;

		if (pkt_buffer_len(buffer) < len)
			return -1;

		/*
		 * TS29.281
		 * 5.2.1 General format of the GTP-U Extension Header
		 *
		 * If no such Header follows,
		 * then the value of the Next Extension Header Type shall be 0. */
		while (*(ext_h = (buffer->head + len - 1))) {
			/*
		 	 * The length of the Extension header shall be defined
		 	 * in a variable length of 4 octets, i.e. m+1 = n*4 octets,
			 * where n is a positive integer.
			 */
			len += (*(++ext_h)) * 4;
			if (pkt_buffer_len(buffer) < len)
				return -1;
		}
	} else if (gtph->flags & (GTPU_FL_S|GTPU_FL_PN)) {
		/*
		 * If and only if one or more of these three flags are set,
		 * the fields Sequence Number, N-PDU and Extension Header
		 * shall be present. The sender shall set all the bits of
		 * the unused fields to zero. The receiver shall not evaluate
		 * the unused fields.
		 * For example, if only the E flag is set to 1, then
		 * the N-PDU Number and Sequence Number fields shall also be present,
		 * but will not have meaningful values and shall not be evaluated.
		 */
		len += 4;
	}

	return (pkt_buffer_len(buffer) < len) ? -1 : len;
}


/*
 *	Stringify enum gtp_flags of flags
 */
static const char *gtp_flags_strs[] = {
	[GTP_FL_RUNNING_BIT] = "GTP_FL_RUNNING_BIT",
	[GTP_FL_STARTING_BIT] = "GTP_FL_STARTING_BIT",
	[GTP_FL_STOPPING_BIT] = "GTP_FL_STOPPING_BIT",
	[GTP_FL_HASHED_BIT] = "GTP_FL_HASHED_BIT",
	[GTP_FL_CTL_BIT] = "GTP_FL_CTL_BIT",
	[GTP_FL_UPF_BIT] = "GTP_FL_UPF_BIT",
	[GTP_FL_FORCE_PGW_BIT] = "GTP_FL_FORCE_PGW_BIT",
	[GTP_FL_IPTNL_BIT] = "GTP_FL_IPTNL_BIT",
	[GTP_FL_DIRECT_TX_BIT] = "GTP_FL_DIRECT_TX_BIT",
	[GTP_FL_SESSION_EXPIRATION_DELETE_TO_BIT] = "GTP_FL_SESSION_EXPIRATION_DELETE_TO_BIT",
	[GTP_FL_GTPC_INGRESS_BIT] = "GTP_FL_GTPC_INGRESS_BIT",
	[GTP_FL_GTPC_EGRESS_BIT] = "GTP_FL_GTPC_EGRESS_BIT",
	[GTP_FL_GTPU_INGRESS_BIT] = "GTP_FL_GTPU_INGRESS_BIT",
	[GTP_FL_GTPU_EGRESS_BIT] = "GTP_FL_GTPU_EGRESS_BIT",
};

char *
gtp_flags2str(char *str, size_t str_len, unsigned long flags)
{
	const char *fl_str;
	int cnt = 0, i;

	if (!str || !str_len)
		return NULL;

	str[0] = '\0';

	for (i = 0; i < ARRAY_SIZE(gtp_flags_strs); i++) {
		if (!__test_bit(i, &flags))
			continue;

		fl_str = gtp_flags_strs[i] ? gtp_flags_strs[i] : "null";
		if (cnt++)
			bsd_strlcat(str, ", ", str_len - strlen(str) - 1);
		bsd_strlcat(str, fl_str, str_len - strlen(str) - 1);
	}

	return str;
}

/*
 *	MSG Types defs
 */
// static const gtp_msg_type_map_t gtp1c_msg_type2str[0xff] = {
// 	[GTP1C_ECHO_REQUEST_TYPE] = {
// 		.name = "GTP1C_ECHO_REQUEST_TYPE",
// 		.description = "Used to check GTP control-plane connectivity between two nodes."
// 	},
// 	[GTP1C_ECHO_RESPONSE_TYPE] = {
// 		 .name = "GTP1C_ECHO_RESPONSE_TYPE",
// 		 .description = "Response confirming connectivity to a GTP Echo Request."
// 	},
// 	[GTP1C_VERSION_NOT_SUPPORTED_INDICATION_TYPE] = {
// 		 .name = "GTP1C_VERSION_NOT_SUPPORTED_INDICATION_TYPE",
// 		 .description = "Indicates that the requested GTP version is not supported."
// 	},
// 	[GTP1C_CREATE_PDP_CONTEXT_REQUEST] = {
// 		.name = "GTP1C_CREATE_PDP_CONTEXT_REQUEST",
// 		.description = "Requests the creation of a PDP context for a subscriber session."
// 	},
// 	[GTP1C_CREATE_PDP_CONTEXT_RESPONSE] = {
// 		.name = "GTP1C_CREATE_PDP_CONTEXT_RESPONSE",
// 		.description = "Returns acceptance or rejection of a Create PDP Context Request."
// 	},
// 	[GTP1C_UPDATE_PDP_CONTEXT_REQUEST] = {
// 		.name = "GTP1C_UPDATE_PDP_CONTEXT_REQUEST",
// 		.description = "Requests modification of an existing PDP context."
// 	},
// 	[GTP1C_UPDATE_PDP_CONTEXT_RESPONSE] = {
// 		.name = "GTP1C_UPDATE_PDP_CONTEXT_RESPONSE",
// 		.description = "Returns acceptance or rejection of an Update PDP Context Request."
// 	},
// 	[GTP1C_DELETE_PDP_CONTEXT_REQUEST] = {
// 		.name = "GTP1C_DELETE_PDP_CONTEXT_REQUEST",
// 		.description = "Requests deletion of an existing PDP context."
// 	},
// 	[GTP1C_DELETE_PDP_CONTEXT_RESPONSE] = {
// 		.name = "GTP1C_DELETE_PDP_CONTEXT_RESPONSE",
// 		.description = "Returns acceptance or rejection of a Delete PDP Context Request."
// 	},
// 	/* any non listed records: 0 initialiazed */
// };

static const gtp_msg_type_map_t gtp2c_msg_type2str[0xff] = {
	[GTP2C_ECHO_REQUEST_TYPE] = {
		.name = "GTP2C_ECHO_REQUEST_TYPE",
		.description = "Used to check GTP control-plane connectivity between two nodes."
	},
	[GTP2C_ECHO_RESPONSE_TYPE] = {
		 .name = "GTP2C_ECHO_RESPONSE_TYPE",
		 .description = "Response confirming connectivity to a GTP Echo Request."
	},
	[GTP2C_VERSION_NOT_SUPPORTED_INDICATION_TYPE] = {
		 .name = "GTP2C_VERSION_NOT_SUPPORTED_INDICATION_TYPE",
		 .description = "Indicates that the requested GTP version is not supported."
	},
	[GTP2C_CREATE_SESSION_REQUEST_TYPE] = {
		.name = "GTP2C_CREATE_SESSION_REQUEST_TYPE",
		.description = "Requests establishment of a new session (bearer) in GTPv2."
	},
	[GTP2C_CREATE_SESSION_RESPONSE_TYPE] = {
		.name = "GTP2C_CREATE_SESSION_RESPONSE_TYPE",
		.description = "Returns acceptance or rejection of a Create Session Request."
	},
	[GTP2C_MODIFY_BEARER_REQUEST_TYPE] = {
		.name = "GTP2C_MODIFY_BEARER_REQUEST_TYPE",
		.description = "Requests modification of parameters for an existing bearer."
	},
	[GTP2C_MODIFY_BEARER_RESPONSE_TYPE] = {
		.name = "GTP2C_MODIFY_BEARER_RESPONSE_TYPE",
		.description = "Returns acceptance or rejection of a Modify Bearer Request."
	},
	[GTP2C_DELETE_SESSION_REQUEST_TYPE] = {
		.name = "GTP2C_DELETE_SESSION_REQUEST_TYPE",
		.description = "Requests deletion of a session (bearer)."
	},
	[GTP2C_DELETE_SESSION_RESPONSE_TYPE] = {
		.name = "GTP2C_DELETE_SESSION_RESPONSE_TYPE",
		.description = "Returns acceptance or rejection of a Delete Session Request."
	},
	[GTP2C_CHANGE_NOTIFICATION_REQUEST] = {
		.name = "GTP2C_CHANGE_NOTIFICATION_REQUEST",
		.description = "Requests a notification regarding changes in user-plane parameters."
	},
	[GTP2C_CHANGE_NOTIFICATION_RESPONSE] = {
		.name = "GTP2C_CHANGE_NOTIFICATION_RESPONSE",
		.description = "Returns acceptance or rejection of a Change Notification Request."
	},
	[GTP2C_REMOTE_UE_REPORT_NOTIFICATION] = {
		.name = "GTP2C_REMOTE_UE_REPORT_NOTIFICATION",
		.description = "Notifies about remote UE events or connectivity changes."
	},
	[GTP2C_RESUME_NOTIFICATION] = {
		.name = "GTP2C_RESUME_NOTIFICATION",
		.description = "Indicates the resumption of suspended data forwarding or session."
	},
	[GTP2C_RESUME_ACK] = {
		.name = "GTP2C_RESUME_ACK",
		.description = "Acknowledges receipt of a GTP Resume Notification."
	},
	[GTP2C_MODIFY_BEARER_COMMAND] = {
		.name = "GTP2C_MODIFY_BEARER_COMMAND",
		.description = "Instructs modification of a bearer with new parameters."
	},
	[GTP2C_MODIFY_BEARER_FAILURE_IND] = {
		.name = "GTP2C_MODIFY_BEARER_FAILURE_IND",
		.description = "Indicates a failure in processing a Modify Bearer Command."
	},
	[GTP2C_DELETE_BEARER_COMMAND] = {
		.name = "GTP2C_DELETE_BEARER_COMMAND",
		.description = "Requests the deletion of a specific bearer."
	},
	[GTP2C_DELETE_BEARER_FAILURE_IND] = {
		.name = "GTP2C_DELETE_BEARER_FAILURE_IND",
		.description = "Indicates a failure in processing a Delete Bearer Command."
	},
	[GTP2C_BEARER_RESSOURCE_COMMAND] = {
		.name = "GTP2C_BEARER_RESSOURCE_COMMAND",
		.description = "Instructs resource allocation or modification for a bearer."
	},
	[GTP2C_BEARER_RESSOURCE_FAILURE_IND] = {
		.name = "GTP2C_BEARER_RESSOURCE_FAILURE_IND",
		.description = "Indicates failure in a bearer resource procedure."
	},
	[GTP2C_CREATE_BEARER_REQUEST] = {
		.name = "GTP2C_CREATE_BEARER_REQUEST",
		.description = "Requests creation of one or more dedicated bearers."
	},
	[GTP2C_CREATE_BEARER_RESPONSE] = {
		.name = "GTP2C_CREATE_BEARER_RESPONSE",
		.description = "Returns acceptance or rejection of a Create Bearer Request."
	},
	[GTP2C_UPDATE_BEARER_REQUEST] = {
		.name = "GTP2C_UPDATE_BEARER_REQUEST",
		.description = "Requests modification of one or more existing bearers."
	},
	[GTP2C_UPDATE_BEARER_RESPONSE] = {
		.name = "GTP2C_UPDATE_BEARER_RESPONSE",
		.description = "Returns acceptance or rejection of an Update Bearer Request."
	},
	[GTP2C_DELETE_BEARER_REQUEST] = {
		.name = "GTP2C_DELETE_BEARER_REQUEST",
		.description = "Requests deletion of one or more bearers."
	},
	[GTP2C_DELETE_BEARER_RESPONSE] = {
		.name = "GTP2C_DELETE_BEARER_RESPONSE",
		.description = "Returns acceptance or rejection of a Delete Bearer Request."
	},
	[GTP2C_DELETE_PDN_CONNECTION_SET_REQUEST] = {
		.name = "GTP2C_DELETE_PDN_CONNECTION_SET_REQUEST",
		.description = "Requests deletion of PDN connections associated with a user."
	},
	[GTP2C_SUSPEND_NOTIFICATION] = {
		.name = "GTP2C_SUSPEND_NOTIFICATION",
		.description = "Indicates the suspension of a PDN connection or bearer."
	},
	[GTP2C_UPDATE_PDN_CONNECTION_SET_REQUEST] = {
		.name = "GTP2C_UPDATE_PDN_CONNECTION_SET_REQUEST",
		.description = "Requests updating PDN connections associated with a user."
	},
	[GTP2C_UPDATE_PDN_CONNECTION_SET_RESPONSE] = {
		.name = "GTP2C_UPDATE_PDN_CONNECTION_SET_RESPONSE",
		.description = "Returns acceptance or rejection of an Update PDN Connection Set Request."
	},
	/* any non listed records: 0 initialiazed */
};

static const gtp_msg_type_map_t gtp1u_msg_type2str[256] = {
	[GTPU_ECHO_REQ_TYPE] = {
		.name = "GTPU_ECHO_REQ_TYPE",
		.description = "Used to verify path connectivity in GTP-U (Echo Request)."
	},
	[GTPU_ECHO_RSP_TYPE] = {
		.name = "GTPU_ECHO_RSP_TYPE",
		.description = "Response confirming path connectivity (Echo Response)."
	},
	[GTPU_ERR_IND_TYPE] = {
		.name = "GTPU_ERR_IND_TYPE",
		.description = "Indicates an error in the user-plane path (e.g., TEID mismatch)."
	},
	[GTPU_SUPP_EXTHDR_NOTI_TYPE] = {
		.name = "GTPU_SUPP_EXTHDR_NOTI_TYPE",
		.description = "Notification that the GTP-U entity supports extension headers."
	},
	[GTPU_END_MARKER_TYPE] = {
		.name = "GTPU_END_MARKER_TYPE",
		.description = "Marks the end of data forwarding during a handover procedure."
	},
	[GTPU_GPDU_TYPE] = {
		.name = "GTPU_GPDU_TYPE",
		.description = "The G-PDU (payload) message that carries user data over GTP-U."
	},
	/* any non listed records: 0 initialiazed */
};

const char *
gtp_msgtype2str(int type, int idx)
{
	const gtp_msg_type_map_t *msg_type2str = NULL;

	if (type == GTP_FL_CTL_BIT)
		msg_type2str = gtp2c_msg_type2str;
	else if (type == GTP_FL_UPF_BIT)
		msg_type2str = gtp1u_msg_type2str;

	if (!msg_type2str)
		return "null";

	if (msg_type2str[idx].name)
		return msg_type2str[idx].name;

	return "bad type";
}

/*
 *	Cause defs
 */
static const gtp_msg_type_map_t gtp1c_msg_cause2str[0xff] = {
	[GTP1C_CAUSE_REQUEST_ACCEPTED] = {
		.name = "GTP1C_CAUSE_REQUEST_ACCEPTED",
		.description = "Cause (GTPv1): request accepted by the receiving node."
	},
	[GTP1C_CAUSE_NON_EXISTENT] = {
		.name = "GTP1C_CAUSE_NON_EXISTENT",
		.description = "Cause (GTPv1): requested resource or context doesn't exist."
	},
	/* any non listed records: 0 initialiazed */
};

static const gtp_msg_type_map_t gtp2c_msg_cause2str[0xff] = {
	[GTP2C_CAUSE_REQUEST_ACCEPTED] = {
		.name = "GTP2C_CAUSE_REQUEST_ACCEPTED",
		.description = "Cause: request accepted by the receiving node."
	},
	[GTP2C_CAUSE_CONTEXT_NOT_FOUND] = {
		.name = "GTP2C_CAUSE_CONTEXT_NOT_FOUND",
		.description = "Cause: session or context not found for the request."
	},
	[GTP2C_CAUSE_MISSING_OR_UNKNOWN_APN] = {
		.name = "GTP2C_CAUSE_MISSING_OR_UNKNOWN_APN",
		.description = "Cause: the APN is missing or not recognized by the network."
	},
	[GTP2C_CAUSE_ALL_DYNAMIC_ADDRESS_OCCUPIED] = {
		.name = "GTP2C_CAUSE_ALL_DYNAMIC_ADDRESS_OCCUPIED",
		.description = "Cause: no free IP addresses left to assign (all in use)."
	},
	[GTP2C_CAUSE_USER_AUTH_FAILED] = {
		.name = "GTP2C_CAUSE_USER_AUTH_FAILED",
		.description = "Cause: user authentication procedure failed."
	},
	[GTP2C_CAUSE_APN_ACCESS_DENIED] = {
		.name = "GTP2C_CAUSE_APN_ACCESS_DENIED",
		.description = "Cause: access to the requested APN is denied."
	},
	[GTP2C_CAUSE_REQUEST_REJECTED] = {
		.name = "GTP2C_CAUSE_REQUEST_REJECTED",
		.description = "Cause: the request was rejected (general failure)."
	},
	[GTP2C_CAUSE_IMSI_IMEI_NOT_KNOWN] = {
		.name = "GTP2C_CAUSE_IMSI_IMEI_NOT_KNOWN",
		.description = "Cause: the IMSI or IMEI is not recognized by the network."
	},
	[GTP2C_CAUSE_INVALID_PEER] = {
		.name = "GTP2C_CAUSE_INVALID_PEER",
		.description = "Cause: the peer node is invalid or not allowed."
	},
	[GTP2C_CAUSE_APN_CONGESTION] = {
		.name = "GTP2C_CAUSE_APN_CONGESTION",
		.description = "Cause: the APN is congested."
	},
	[GTP2C_CAUSE_MULTIPLE_PDN_NOT_ALLOWED] = {
		.name = "GTP2C_CAUSE_MULTIPLE_PDN_NOT_ALLOWED",
		.description = "Cause: subscriber restricted to a single PDN connection."
	},
	[GTP2C_CAUSE_TIMED_OUT_REQUEST] = {
		.name = "GTP2C_CAUSE_TIMED_OUT_REQUEST",
		.description = "Cause: no response before the request timed out."
	},
	[GTP2C_CAUSE_5GC_NOT_ALLOWED] = {
		.name = "GTP2C_CAUSE_5GC_NOT_ALLOWED",
		.description = "Cause: requested 5G Core functionality not allowed."
	},
	/* any non listed records: 0 initialiazed */
};


const char *
gtp2c_cause2str(int idx)
{
	if (gtp2c_msg_cause2str[idx].name)
		return gtp2c_msg_cause2str[idx].name;

	return "bad cause";
}

const char *
gtp1c_cause2str(int idx)
{
	if (gtp1c_msg_cause2str[idx].name)
		return gtp1c_msg_cause2str[idx].name;

	return "bad cause";
}

