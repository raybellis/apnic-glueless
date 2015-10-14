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

#ifndef __LDNSUTILS_H
#define __LDNSUTILS_H

#include <ldns/ldns.h>

#ifdef __cplusplus
extern "C" {
#endif

ldns_dnssec_zone *util_load_zone(const ldns_rdf *origin, const char *zonefile);
ldns_key_list *util_load_key(const ldns_rdf *origin, const char *keyfile);
ldns_status util_sign_zone(ldns_dnssec_zone *zone, ldns_key_list *keys);

#ifdef __cplusplus
}
#endif

#endif /* __LDNSUTILS_H */
