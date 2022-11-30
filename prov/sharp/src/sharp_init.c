/*
 * Copyright (c) 2022 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <rdma/fi_errno.h>

#include <ofi_prov.h>
#include "sharp.h"

struct sharp_env sharp_env = {
	.ib_port = 1,
};

static void sharp_init_env(void)
{
	fi_param_get_size_t(&sharp_prov, "ib_port", &sharp_env.ib_port);
}

static int sharp_getinfo(uint32_t version, const char *node, const char *service,
		       uint64_t flags, const struct fi_info *hints,
		       struct fi_info **info)
{
	int ret;

	ret = util_getinfo(&sharp_util_prov, version, node, service, flags,
			   hints, info);
	if (ret)
		return ret;

	return 0;
}

static void sharp_fini(void)
{
#if HAVE_SHARP_DL
	ofi_hmem_cleanup();
#endif
}

struct fi_provider sharp_prov = {
	.name = OFI_OFFLOAD_PREFIX "sharp",
	.version = OFI_VERSION_DEF_PROV,
	.fi_version = OFI_VERSION_LATEST,
	.getinfo = sharp_getinfo,
	.fabric = sharp_fabric,
	.cleanup = sharp_fini
};

/// @brief XXX to be moved to sharp_attr.c
struct util_prov sharp_util_prov = {
	.prov = &sharp_prov,
	.info = &sharp_info,
	.flags = 0
};

SHARP_INI
{
#if HAVE_SHARP_DL
	ofi_hmem_init();
#endif
	fi_param_define(&sharp_prov, "ib_port", FI_PARAM_INT,
			"IB device port used by SHARP \
			 Default: 1");

	sharp_init_env();
	return &sharp_prov;
}
