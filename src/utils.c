#include <stdlib.h>
#include <stdio.h>

#include "utils.h"

ldns_dnssec_zone *util_load_zone(const ldns_rdf *origin, const char *zonefile)
{
	ldns_dnssec_zone	*zone;
	ldns_status			status;
	FILE				*fp;

	fp = fopen(zonefile, "r");
	if (!fp) {
		perror("util_load_zone");
		return NULL;
	}

	status = ldns_dnssec_zone_new_frm_fp(&zone, fp, origin, 60, LDNS_RR_CLASS_IN);
	fclose(fp);

	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "error loading zone file: %s\n", ldns_get_errorstr_by_id(status));
		return NULL;
	}

	return zone;
}

ldns_key_list *util_load_key(const ldns_rdf *origin, const char *keyfile)
{
	ldns_key_list		*list;
	ldns_key			*key;
	ldns_status			status;
	FILE				*fp;

	fp = fopen(keyfile, "r");
	if (!fp) {
		perror("util_load_key");
		return NULL;
	}

	status = ldns_key_new_frm_fp(&key, fp);
	fclose(fp);

	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "error loading key file: %s\n", ldns_get_errorstr_by_id(status));
		return NULL;
	}

	list = ldns_key_list_new();
	ldns_key_set_pubkey_owner(key, ldns_rdf_clone(origin));
	ldns_key_set_inception(key, time(NULL) - 3600);
	ldns_key_list_push_key(list, key);

	return list;
}

ldns_status util_sign_zone(ldns_dnssec_zone *zone, ldns_key_list *keys)
{
	ldns_rr_list		*new_rrs;
	ldns_status			status;

	/* add all the keys to the zone */
	for (int i = 0, n = ldns_key_list_key_count(keys); i < n; ++i) {
		ldns_rr *rr = ldns_key2rr(ldns_key_list_key(keys, i));
		ldns_dnssec_zone_add_rr(zone, rr);
	}

	/* sign the zone, then discard the extra list of RRs */
	new_rrs = ldns_rr_list_new();
	status = ldns_dnssec_zone_sign(zone, new_rrs, keys, ldns_dnssec_default_replace_signatures, 0);
	ldns_rr_list_free(new_rrs);

	return status;
}
