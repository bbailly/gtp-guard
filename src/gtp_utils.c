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
		return GTPV1C_HEADER_LEN_SHORT;

	return GTPV1C_HEADER_LEN_LONG;
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

int
gtpv1_uli_rewrite_geographic_location(gtp_plmn_t* override_plmn, struct sockaddr_in *sgsn_addr, gtp1_ie_uli_t *uli, pkt_buffer_t *pkt)
{
	uint8_t *cp = (uint8_t *) uli;
	int delta = 0;

	log_message(LOG_DEBUG, "%s(): trying to overwrite gtpv1 ULI"
		, __FUNCTION__);


	memcpy(uli->mcc_mnc, &override_plmn->plmn, sizeof(override_plmn->plmn));
	uli->geographic_location_type = GTP1_ULI_GEOGRAPHIC_LOCATION_TYPE_CGI;
	uli->geographic_location.geographic_location_value = ntohl(sgsn_addr->sin_addr.s_addr);
	log_message(LOG_DEBUG, "%s(): sgw_addr=0x%08x, geographic_location_type=0x%02x, geographic_location_value=0x%08x"
		, __FUNCTION__
		, ntohl(sgsn_addr->sin_addr.s_addr), uli->geographic_location_type, uli->geographic_location.geographic_location_value);

	/* Override PLMN and write SGSN IPv4 address */
	memcpy((uint8_t *)cp, uli, sizeof(gtp1_ie_uli_t) - sizeof(uli->geographic_location.geographic_location_value));
	uint32_t geographic_location_value_to_send = htonl(uli->geographic_location.geographic_location_value);
	memcpy((uint8_t *)cp + sizeof(gtp1_ie_uli_t) - sizeof(uli->geographic_location.geographic_location_value), &geographic_location_value_to_send, sizeof(geographic_location_value_to_send));
	return delta;
}


int
gtpv1_ie_uli_rewrite(gtp_plmn_t* override_plmn, struct sockaddr_in *sgw_addr, gtp1_ie_uli_t *ie_uli, pkt_buffer_t *buffer)
{
	return gtpv1_uli_rewrite_geographic_location(override_plmn, sgw_addr, ie_uli,buffer);
}


int
gtpv1_ie_uli_add(gtp_plmn_t* override_plmn, struct sockaddr_in *sgw_addr, pkt_buffer_t *buffer)
{
	uint8_t *cp;
	int tail_len;

	log_message(LOG_DEBUG, "%s(): a ULI will be added"
		, __FUNCTION__);

	/* Find Serving Network IE or RAT TYPE IE to add ULI IE before */
	cp = gtp1_get_ie(GTP1_IE_QOS_PROFILE_TYPE, buffer);
	if(!cp){
		log_message(LOG_WARNING, "%s(): Can't add ULI IE because no QoS Profile IE is present !!!"
			, __FUNCTION__);
		return 0;
	}

	uint16_t delta = sizeof(gtp1_ie_uli_t);
	/* Bounds checking */
	if (pkt_buffer_tailroom(buffer) < delta) {
		log_message(LOG_WARNING, "%s(): Warning Bounds Check failed pkt_tailroom:%d delta:%d !!!"
			, __FUNCTION__
			, pkt_buffer_tailroom(buffer), delta);
		return 0;
	}
	tail_len = buffer->end - cp;
	/* Move end of the packet to have space to introduce an eCGI*/
	memmove(cp + delta, cp, tail_len);

	gtp1_hdr_t *gtph = (gtp1_hdr_t *) buffer->head;
	gtph->length = htons(ntohs(gtph->length) + delta);
	buffer->end += delta;
	gtp1_ie_uli_t uli;
	uli.h.length = htons(sizeof(gtp1_ie_uli_t) - sizeof(gtp1_ie_t));
	uli.h.type = GTP1_IE_ULI_TYPE;
	memcpy(cp, &uli, sizeof(gtp1_ie_uli_t));

	return gtpv1_uli_rewrite_geographic_location(override_plmn, sgw_addr, (gtp1_ie_uli_t *)cp,buffer) + delta;
}


/*
 *      GTPv2 utilities
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

int
gtpv2_uli_rewrite_ecgi(gtp_plmn_t* override_plmn, struct sockaddr_in *sgw_addr, gtp_ie_uli_t *uli, pkt_buffer_t *pkt)
{
	uint8_t *cp = (uint8_t *) uli;
	int delta = 0, tail_len;

	/* Move to the ecgi*/
	size_t offset = 0;
	offset += (uli->cgi) ? sizeof(gtp_id_cgi_t) : 0;
	offset += (uli->sai) ? sizeof(gtp_id_sai_t) : 0;
	offset += (uli->rai) ? sizeof(gtp_id_rai_t) : 0;
	offset += (uli->tai) ? sizeof(gtp_id_tai_t) : 0;
	/* Grouped identities in following order according
	* to presence in previous bitfield:
	CGI / SAI / RAI / TAI / ECGI / LAI / MacroeNBID / extMacroeNBID */
	cp += sizeof(gtp_ie_uli_t) + offset;

	/* if no ecgi add it */
	if (!uli->ecgi){
		log_message(LOG_DEBUG, "%s(): a ecgi will be added in ULI"
			, __FUNCTION__);

		/* Bounds checking */
		delta = sizeof(gtp_id_ecgi_t);
		if (pkt_buffer_tailroom(pkt) < delta) {
			log_message(LOG_WARNING, "%s(): Warning Bounds Check failed pkt_tailroom:%d delta:%d !!!"
				, __FUNCTION__
				, pkt_buffer_tailroom(pkt), delta);
			return 0;
		}
		tail_len = pkt->end - cp;
		/* Move end of the packet to have space to introduce an eCGI*/
		memmove(cp + delta, cp, tail_len);

		/* Change the eCGI flag in ULI header */
		uli->ecgi = 1;

		/* Update IE length, message length and packet length */
		uli->h.length = htons(ntohs(uli->h.length) + delta);
		gtp_hdr_t *gtph = (gtp_hdr_t *) pkt->head;
		gtph->length = htons(ntohs(gtph->length) + delta);
		pkt->end += delta;
	}
	log_message(LOG_DEBUG, "%s(): trying to overwrite ecgi"
		, __FUNCTION__);


	gtp_id_ecgi_t ecgi;
	memcpy(&ecgi.mcc_mnc, override_plmn->plmn,sizeof(ecgi.mcc_mnc));
	ecgi.u.ecgi_raw = ntohl(sgw_addr->sin_addr.s_addr);
	log_message(LOG_DEBUG, "%s(): sgw_addr=0x%08x, spare=0x%01x, enbid=0x%05x, cellid=0x%02x"
		, __FUNCTION__
		, ntohl(sgw_addr->sin_addr.s_addr), ecgi.u.ecgi_struct.spare, ecgi.u.ecgi_struct.enbid, ecgi.u.ecgi_struct.cellid);

	/* Override PLMN and write SGW IPv4 address */
	const uint32_t ecgi_to_send = htonl(ecgi.u.ecgi_raw);
	memcpy((uint8_t *)cp, &ecgi.mcc_mnc, sizeof(ecgi.mcc_mnc));
	memcpy((uint8_t *)cp + sizeof(ecgi.mcc_mnc), &ecgi_to_send, sizeof(ecgi_to_send));

	return delta;
}


int
gtpv2_ie_uli_rewrite(gtp_plmn_t* override_plmn, struct sockaddr_in *sgw_addr, gtp_ie_uli_t *ie_uli, pkt_buffer_t *buffer)
{
	return gtpv2_uli_rewrite_ecgi(override_plmn, sgw_addr, ie_uli, buffer);
}


int
gtpv2_ie_uli_add(gtp_plmn_t* override_plmn, struct sockaddr_in *sgw_addr, pkt_buffer_t *buffer)
{
	uint8_t *cp;
	int tail_len;

	log_message(LOG_DEBUG, "%s(): a ULI will be added"
		, __FUNCTION__);

	/* Find Serving Network IE or RAT TYPE IE to add ULI IE before */
	cp = gtp_get_ie(GTP_IE_SERVING_NETWORK_TYPE, buffer);
	if(!cp){
		cp = gtp_get_ie(GTP_IE_RAT_TYPE_TYPE, buffer);
		if(!cp){
			log_message(LOG_WARNING, "%s(): Can't add ULI IE because no Serving Network IE and RAT TYPE IE are present !!!"
				, __FUNCTION__);
			return 0;
		}
	}

	uint16_t delta = sizeof(gtp_ie_uli_t);
	/* Bounds checking */
	if (pkt_buffer_tailroom(buffer) < delta) {
		log_message(LOG_WARNING, "%s(): Warning Bounds Check failed pkt_tailroom:%d delta:%d !!!"
			, __FUNCTION__
			, pkt_buffer_tailroom(buffer), delta);
		return 0;
	}
	tail_len = buffer->end - cp;
	/* Move end of the packet to have space to introduce an eCGI*/
	memmove(cp + delta, cp, tail_len);

	gtp_hdr_t *gtph = (gtp_hdr_t *) buffer->head;
	gtph->length = htons(ntohs(gtph->length) + delta);
	buffer->end += delta;
	gtp_ie_uli_t uli;
	uli.h.instance = 0;
	uli.h.length = htons(1);
	uli.h.type = GTP_IE_ULI_TYPE;
	uli.cgi = 0;
	uli.ecgi = 0;
	uli.extended_macro_enbid = 0;
	uli.lai = 0;
	uli.macro_enbid = 0;
	uli.rai = 0;
	uli.sai = 0;
	uli.tai = 0;
	memcpy(cp, &uli, sizeof(gtp_ie_uli_t));

	return gtpv2_uli_rewrite_ecgi(override_plmn, sgw_addr, (gtp_ie_uli_t *)cp,buffer) + delta;
}

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

gtp_id_ecgi_t *
gtp_ie_uli_extract_ecgi(gtp_ie_uli_t *uli)
{
	size_t offset = 0;

	if (!uli->ecgi)
		return NULL;

	offset += (uli->cgi) ? sizeof(gtp_id_cgi_t) : 0;
	offset += (uli->sai) ? sizeof(gtp_id_sai_t) : 0;
	offset += (uli->rai) ? sizeof(gtp_id_rai_t) : 0;
	offset += (uli->tai) ? sizeof(gtp_id_tai_t) : 0;

	/* overflow protection */
	if (offset + sizeof(gtp_id_ecgi_t) > ntohs(uli->h.length))
		return NULL;

	offset += sizeof(gtp_ie_uli_t);
	return (gtp_id_ecgi_t *) ((uint8_t *)uli + offset);
}

int
gtp_id_ecgi_str(gtp_id_ecgi_t *ecgi, char *buffer, size_t size)
{
	int mcc, mnc;

	if (!ecgi) {
		strlcpy(buffer, "0+0+0+0", size);
		return -1;
	}

	mcc = bcd_to_int64(ecgi->mcc_mnc, 2);
	mnc = bcd_to_int64(ecgi->mcc_mnc+2, 1);

	return snprintf(buffer, size, "%d+%d+%d+%d"
			      , mcc, mnc, ntohl(ecgi->u.ecgi_struct.enbid), ecgi->u.ecgi_struct.cellid);
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


/*
 *      GTP-U related
 */
ssize_t
gtpu_get_header_len(pkt_buffer_t *buffer)
{
	ssize_t len = GTPV1U_HEADER_LEN;
	gtp_hdr_t *gtph = (gtp_hdr_t *) buffer->head;
	uint8_t *ext_h = NULL;

	if (pkt_buffer_len(buffer) < len)
		return -1;

	if (gtph->flags & GTPU_FL_E) {
	        len += GTPV1U_EXTENSION_HEADER_LEN;

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
