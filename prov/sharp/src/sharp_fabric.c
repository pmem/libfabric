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

#include <stdlib.h>
#include <string.h>

#include "sharp.h"

static struct fi_ops_fabric sharp_fabric_ops = {
	.size = sizeof(struct fi_ops_fabric),
	.domain = fi_no_domain,
	.passive_ep = fi_no_passive_ep,
	.eq_open = sharp_eq_open,
	.wait_open = fi_no_wait_open,
	.trywait = ofi_trywait,
	.domain2 = sharp_domain2
};

static int sharp_fabric_close(fid_t fid)
{
	int ret;
	struct util_fabric *fabric;

	fabric = container_of(fid, struct util_fabric, fabric_fid.fid);

	ret = ofi_fabric_close(fabric);
	if (ret)
		return ret;

	free(fabric);
	return 0;
}

static struct fi_ops sharp_fabric_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = sharp_fabric_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

/*
XXX to be added to fabric.h later
*/
static inline void 
fid_fabric_init(struct fid_fabric **fabric_fid,
		struct util_fabric *util_fabric, struct fi_ops *fid_ops,
		struct fi_ops_fabric *ops)
{
	*fabric_fid = &util_fabric->fabric_fid;
	(*fabric_fid)->fid.ops = fid_ops;
	(*fabric_fid)->ops = ops;
}

int sharp_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric_fid,
		void *context)
{
	int ret;
	struct sharp_fabric *fabric;

	fabric = calloc(1, sizeof(*fabric));
	if (!fabric)
		return -FI_ENOMEM;

	ret = ofi_fabric_init(&sharp_prov, &sharp_fabric_attr, attr,
			      &fabric->util_fabric, context);
	if (ret)
		goto err;

#if 0
	/* XXX to be removed later */
	*fabric_fid = &fabric->util_fabric.fabric_fid; 
	(*fabric_fid)->fid.ops = &sharp_fabric_fi_ops;
	(*fabric_fid)->ops = &sharp_fabric_ops;
#endif
	fid_fabric_init(fabric_fid, &fabric->util_fabric, &sharp_fabric_fi_ops,
		&sharp_fabric_ops);
	return 0;

err:
	free(fabric);
	return ret;
}
