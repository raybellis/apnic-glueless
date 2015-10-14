/*
 * Copyright (C) 2015       Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "evutils.h"

void query_check(evldns_server_request *srq,
				 ATTR_UNUSED(void *user_data),
				 ATTR_UNUSED(ldns_rdf *qname),
				 ldns_rr_type qtype,
				 ldns_rr_class qclass)
{
	ldns_pkt *req = srq->request;

	/* only QUERY is supported */
	if (ldns_pkt_get_opcode(req) != LDNS_PACKET_QUERY) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
		return;
	}

	/* QDCOUNT == 1, NB: QR == 1 now handled upstream */
	if (ldns_pkt_qdcount(req) != 1) {
		srq->response = evldns_response(req, LDNS_RCODE_FORMERR);
		return;
	}

	/* Unexpected QCLASS */
	if (qclass != LDNS_RR_CLASS_IN) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
		return;
	}

	/* Unexpected QTYPE */
	if (qtype == LDNS_RR_TYPE_AXFR || qtype == LDNS_RR_TYPE_IXFR) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
		return;
	}

	/* Not going to handle QTYPE == ANY either */
	if (qtype == LDNS_RR_TYPE_ANY) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
		return;
	}
}
