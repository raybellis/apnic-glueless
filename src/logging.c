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

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <netdb.h>
#include <evldns.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

static int log_open(const char *fmt, time_t t)
{
	static int logfd = -1;
	static time_t last = 0;

	if (logfd < 0 || t > last) {
		int newfd;
		char path[_POSIX_PATH_MAX];
		strftime(path, _POSIX_PATH_MAX, fmt, gmtime(&t));

		newfd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
		if (logfd >= 0) {
			dup2(newfd, logfd);
			close(newfd);
		} else {
			logfd = newfd;
		}
	}

	return logfd;
}

void log_request(const char *fmt, evldns_server_request *srq, const ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass)
{
	struct timeval tv;
	char *qname_str, *qclass_str, *qtype_str;
	ldns_buffer *qname_buf;
	char logbuffer[2048];
	char host[NI_MAXHOST], port[NI_MAXSERV];
	ldns_pkt *req, *resp;
	int edns, do_bit;
	int n;

	gettimeofday(&tv, NULL);
	req = srq->request;
	resp = srq->response;

	// request flags
	edns = ldns_pkt_edns(req);
	do_bit = edns && ldns_pkt_edns_do(req);

	// src IP and port
	if (getnameinfo((struct sockaddr *)&srq->addr, srq->addrlen,
			host, sizeof(host),
			port, sizeof(port),
			NI_NUMERICHOST | NI_NUMERICSERV) != 0)
	{
		strcpy(host, "unknown");
		strcpy(port, "0");
	}

	qname_buf = ldns_buffer_new(256);
	ldns_rdf2buffer_str_dname(qname_buf, qname);
	qname_str = (char *)ldns_buffer_export(qname_buf);
	qclass_str = ldns_rr_class2str(qclass);
	qtype_str = ldns_rr_type2str(qtype);

	n = snprintf(logbuffer, sizeof(logbuffer),
		"%ld.%06ld client %s#%s: query: %s %s %s %s%s%s%s%s (%s) %d %lu\n",
		(unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec,
		host, port,
		qname_str, qclass_str, qtype_str,
		ldns_pkt_rd(req) ? "+" : "-",	// RD
		edns ? "E" : "",				// EDNS
		srq->is_tcp ? "T": "",			// TCP
		do_bit ? "D": "",				// DO
		ldns_pkt_cd(req) ? "C" : "",	// CD
		"",
		ldns_pkt_get_rcode(resp),		// RCODE
		srq->wire_response ? srq->wire_resplen : 0);

	write(log_open(fmt, tv.tv_sec), logbuffer, n);
	
	free(qname_str);
	free(qtype_str);
	free(qclass_str);
	ldns_buffer_free(qname_buf);
}
