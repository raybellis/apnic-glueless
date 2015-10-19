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

#include <stdexcept>

#include "base.h"
#include "utils.h"
#include "process.h"
#include "logging.h"

class SiblingZone : public Zone {
private:
	ldns_rdf			*wild;

public:
	SiblingZone(const std::string& domain, const std::string& zonefile);
	~SiblingZone();

public:
	void main_callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype);
	void apex_callback(ldns_rdf *qname, ldns_rr_type qtype, ldns_pkt *resp);
	void sub_callback(ldns_rdf *qname, ldns_rr_type qtype, ldns_pkt *resp);
};

SiblingZone::SiblingZone(
	const std::string& domain,
	const std::string& zonefile)
  : Zone(domain, zonefile)
{
	wild = ldns_dname_new_frm_str("*");
	ldns_dname_cat(wild, origin);
}

SiblingZone::~SiblingZone()
{
	ldns_rdf_deep_free(wild);
}

void SiblingZone::main_callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype)
{
	auto req = srq->request;
	auto resp = srq->response = evldns_response(req, LDNS_RCODE_NOERROR);
	auto answer = ldns_pkt_answer(resp);
	auto authority = ldns_pkt_authority(resp);

	if (ldns_dname_compare(qname, origin) == 0) {
		apex_callback(qname, qtype, resp);
	} else if (ldns_dname_is_subdomain(qname, origin)) {
		sub_callback(qname, qtype, resp);
	} else {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_REFUSED);
		return;
	}

	// include the SOA if no answers resulted
	if (ldns_rr_list_rr_count(answer) == 0) {
		auto soa = zone->soa;
		auto rrsets = ldns_dnssec_name_find_rrset(soa, LDNS_RR_TYPE_SOA);
		LDNS_rr_list_cat_dnssec_rrs_clone(authority, rrsets->rrs);
	}

	ldns_pkt_set_ancount(resp, ldns_rr_list_rr_count(answer));
	ldns_pkt_set_nscount(resp, ldns_rr_list_rr_count(authority));
	ldns_pkt_set_aa(resp, 1);
}

void SiblingZone::apex_callback(ldns_rdf *qname, ldns_rr_type qtype, ldns_pkt *resp)
{
	auto answer = ldns_pkt_answer(resp);
	auto authority = ldns_pkt_authority(resp);
	auto rrsets = ldns_dnssec_zone_find_rrset(zone, qname, qtype);
	if (rrsets) {
		LDNS_rr_list_cat_dnssec_rrs_clone(answer, rrsets->rrs);
	} else {
		auto soa = zone->soa;
		rrsets = ldns_dnssec_name_find_rrset(soa, LDNS_RR_TYPE_SOA);
		LDNS_rr_list_cat_dnssec_rrs_clone(authority, rrsets->rrs);
	}
}

void SiblingZone::sub_callback(ldns_rdf *qname, ldns_rr_type qtype, ldns_pkt *resp)
{
	auto answer = ldns_pkt_answer(resp);
	auto authority = ldns_pkt_authority(resp);

	// make sure there's no more than one label and extract that label
	unsigned int qname_count = ldns_dname_label_count(qname);
	if (qname_count != origin_count + 1) {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_NXDOMAIN);
		return;
	}
	auto sub_label = ldns_dname_label(qname, 0);

	// make sure that label isn't a wildcard
	if (ldns_dname_is_wildcard(sub_label)) {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_NXDOMAIN);
	} else {
		// check for wildcard entry
		auto rrsets = ldns_dnssec_zone_find_rrset(zone, wild, qtype);

		// TODO: replace owner names
		if (rrsets) {
			LDNS_rr_list_cat_dnssec_rrs_clone(answer, rrsets->rrs);
		}

		// TODO: add stuffing
	}

	ldns_rdf_deep_free(sub_label);
}

static void dispatch(evldns_server_request *srq, void *userdata, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass)
{
	auto handler = static_cast<SiblingZone *>(userdata);
	handler->main_callback(srq, qname, qtype);
}

struct InstanceData {
	int         *fds;
	SiblingZone	*zone;
};

static void *start_instance(void *userdata)
{
	auto data = reinterpret_cast<InstanceData *>(userdata);

    EVLDNSBase server(data->fds);
    server.add_callback(dispatch, data->zone);
    server.start();

    return NULL;
}

int main(int argc, char *argv[])
{
	int				n_forks = 0;
	int				n_threads = 0;
	const char		*hostname = NULL;
	const char		*port = "5055";
	const char		*domain = "oob.nxdomain.net";
	const char		*zonefile = "data/zone.oob.nxdomain.net";

	SiblingZone		zone(domain, zonefile);
	InstanceData	data = { bind_to_all(hostname, port, 100), &zone };

	farm(n_forks, n_threads, start_instance, &data, 0);

	return 0;
}
