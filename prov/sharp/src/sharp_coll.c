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

#include "sharp.h"

int sharp_query_collective(struct fid_domain *domain,
		enum fi_collective_op coll, struct fi_collective_attr *attr,
		uint64_t flags)
{
	if (!attr || attr->mode != 0)
		return -FI_EINVAL;

	switch (coll) {
	case FI_BARRIER:
		// return FI_SUCCESS; //XXX to be change when barier operation is implemented
	case FI_ALLREDUCE:
		// return FI_SUCCESS; //XXX to be change when allreduce operation is implemented
	case FI_ALLGATHER:
	case FI_SCATTER:
	case FI_BROADCAST:
	case FI_ALLTOALL:
	case FI_REDUCE_SCATTER:
	case FI_REDUCE:
	case FI_GATHER:
	default:
		return -FI_ENOSYS;
	}

	return -FI_ENOSYS;
}

static int sharp_mc_close(struct fid *fid)
{
	struct sharp_mc *mc;

	mc = container_of(fid, struct sharp_mc, mc_fid.fid);
	if (mc->oob_fid_mc) {
		fi_close(&(mc->oob_fid_mc->fid));
		mc->oob_fid_mc = NULL;
	}
	// ofi_atomic_dec32(&mc->ep->ref); //XXX
	free(mc);
	return 0;
}

int	sharp_mc_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct sharp_mc *mc;
	struct fid_mc *fid_mc;
	mc = container_of(fid, struct sharp_mc, mc_fid.fid);
	fid_mc = container_of(bfid, struct fid_mc, fid);
	mc->oob_fid_mc = fid_mc;
	return 0;
}

static struct fi_ops sharp_mc_fid_ops = {
	.size = sizeof(struct fi_ops),
	.close = sharp_mc_close,
	.bind = sharp_mc_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};


int sharp_join_collective(struct fid_ep *fid, const void *addr, uint64_t flags,
		    struct fid_mc **mc_fid, void *context)
{
	struct sharp_mc *mc;
	//XXX struct fi_peer_transfer_context *peer_context = context;

	mc = calloc(1, sizeof(*mc));
	if (!mc)
		return -FI_ENOMEM;

	*mc_fid = &mc->mc_fid;
	(*mc_fid)->fid.ops = &sharp_mc_fid_ops;
	return 0;
}


