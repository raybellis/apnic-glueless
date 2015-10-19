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

#ifndef __BASE_H
#define __BASE_H

#include <string>

#include <evldns.h>

class Base {

private:
	event_base			*ev_base;

protected:
	ldns_dnssec_zone	*zone;
	evldns_server		*ev_server;
	ldns_rdf			*origin;
	unsigned int		origin_count;

public:
	Base(const int *fds, const std::string& domain, const std::string& zonefile);
	~Base();

public:
	void start();
};

class SignedBase : public Base {

protected:
	ldns_key_list		*keys;

public:
	SignedBase(const int *fds, const std::string& domain, const std::string& zonefile, const std::string& keyfile);
	~SignedBase();

public:
	void sign();
};

#endif /* __BASE_H */
