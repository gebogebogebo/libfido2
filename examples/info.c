/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/ec.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../openbsd-compat/openbsd-compat.h"

#include "fido.h"

/*
 * Pretty-print a device's capabilities flags and return the result.
 */
static void
format_flags(char *ret, size_t retlen, uint8_t flags)
{
	memset(ret, 0, retlen);

	if (flags & FIDO_CAP_WINK) {
		if (strlcat(ret, "wink,", retlen) >= retlen)
			goto toolong;
	} else {
		if (strlcat(ret, "nowink,", retlen) >= retlen)
			goto toolong;
	}

	if (flags & FIDO_CAP_CBOR) {
		if (strlcat(ret, " cbor,", retlen) >= retlen)
			goto toolong;
	} else {
		if (strlcat(ret, " nocbor,", retlen) >= retlen)
			goto toolong;
	}

	if (flags & FIDO_CAP_NMSG) {
		if (strlcat(ret, " nomsg", retlen) >= retlen)
			goto toolong;
	} else {
		if (strlcat(ret, " msg", retlen) >= retlen)
			goto toolong;
	}

	return;
toolong:
	strlcpy(ret, "toolong", retlen);
}

/*
 * Print a FIDO device's attributes on stdout.
 */
static void
print_attr(const fido_dev_t *dev)
{
	char flags_txt[128];

	printf("proto: 0x%02x\n", fido_dev_protocol(dev));
	printf("major: 0x%02x\n", fido_dev_major(dev));
	printf("minor: 0x%02x\n", fido_dev_minor(dev));
	printf("build: 0x%02x\n", fido_dev_build(dev));

	format_flags(flags_txt, sizeof(flags_txt), fido_dev_flags(dev));
	printf("caps: 0x%02x (%s)\n", fido_dev_flags(dev), flags_txt);
}

/*
 * Auxiliary function to print an array of strings on stdout.
 */
static void
print_str_array(const char *label, char * const *sa, size_t len)
{
	if (len == 0)
		return;

	printf("%s strings: ", label);

	for (size_t i = 0; i < len; i++)
		printf("%s%s", i > 0 ? ", " : "", sa[i]);

	printf("\n");
}

/*
 * Auxiliary function to print (char *, bool) pairs on stdout.
 */
static void
print_opt_array(const char *label, char * const *name, const bool *value,
    size_t len)
{
	if (len == 0)
		return;

	printf("%s: ", label);

	for (size_t i = 0; i < len; i++)
		printf("%s%s%s", i > 0 ? ", " : "",
		    value[i] ? "" : "no", name[i]);

	printf("\n");
}

/*
 * Auxiliary function to print an authenticator's AAGUID on stdout.
 */
static void
print_aaguid(const unsigned char *buf, size_t buflen)
{
	printf("aaguid: ");

	while (buflen--)
		printf("%02x", *buf++);

	printf("\n");
}

/*
 * Auxiliary function to print an authenticator's maximum message size on
 * stdout.
 */
static void
print_maxmsgsiz(uint64_t maxmsgsiz)
{
	printf("maxmsgsiz: %d\n", (int)maxmsgsiz);
}

/*
 * Auxiliary function to print an array of bytes on stdout.
 */
static void
print_byte_array(const char *label, const uint8_t *ba, size_t len)
{
	if (len == 0)
		return;

	printf("%s: ", label);

	for (size_t i = 0; i < len; i++)
		printf("%s%u", i > 0 ? ", " : "", (unsigned)ba[i]);

	printf("\n");
}

static void
getinfo(const char *path)
{
	fido_dev_t		*dev;
	fido_cbor_info_t	*ci;
	int			 r;

	fido_init(FIDO_DEBUG);
	//fido_init(0);

	if ((dev = fido_dev_new()) == NULL)
		errx(1, "fido_dev_new");
	if ((r = fido_dev_open(dev, path)) != FIDO_OK)
		errx(1, "fido_dev_open: %s (0x%x)", fido_strerr(r), r);

	print_attr(dev);

	if (fido_dev_is_fido2(dev) == false)
		goto end;
	if ((ci = fido_cbor_info_new()) == NULL)
		errx(1, "fido_cbor_info_new");
	if ((r = fido_dev_get_cbor_info(dev, ci)) != FIDO_OK)
		errx(1, "fido_dev_get_cbor_info: %s (0x%x)", fido_strerr(r), r);

	/* print supported protocol versions */
	print_str_array("version", fido_cbor_info_versions_ptr(ci),
	    fido_cbor_info_versions_len(ci));

	/* print supported extensions */
	print_str_array("extension", fido_cbor_info_extensions_ptr(ci),
	    fido_cbor_info_extensions_len(ci));

	/* print aaguid */
	print_aaguid(fido_cbor_info_aaguid_ptr(ci),
	    fido_cbor_info_aaguid_len(ci));

	/* print supported options */
	print_opt_array("options", fido_cbor_info_options_name_ptr(ci),
	    fido_cbor_info_options_value_ptr(ci),
	    fido_cbor_info_options_len(ci));

	/* print maximum message size */
	print_maxmsgsiz(fido_cbor_info_maxmsgsiz(ci));

	/* print supported pin protocols */
	print_byte_array("pin protocols", fido_cbor_info_protocols_ptr(ci),
	    fido_cbor_info_protocols_len(ci));

	fido_cbor_info_free(&ci);
end:
	if ((r = fido_dev_close(dev)) != FIDO_OK)
		errx(1, "fido_dev_close: %s (0x%x)", fido_strerr(r), r);

	fido_dev_free(&dev);
}

int
main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: info <device>\n");
		exit(EXIT_FAILURE);
	}

	printf("info-start\r\n");
	printf("<Device>=%s\r\n", argv[1]);

	getinfo(argv[1]);

	exit(0);
}
