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
	case FI_ALLREDUCE:
		return FI_SUCCESS;
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

#if 0
static int sharp_mc_close(struct fid *fid)
{
#if 0
	struct sharp_mc *mc;

	mc = container_of(fid, struct sharp_mc, mc_fid.fid);
	ofi_atomic_dec32(&mc->ep->ref);
	free(mc);
	return 0;
#else
	return -FI_ENOSYS;
#endif
}

#if 0
static struct fi_ops sharp_mc_ops = {
	.size = sizeof(struct fi_ops),
	.close = sharp_mc_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};
#endif
static struct sharp_mc *sharp_mc_create(struct fid_ep *fid,
	struct util_av_set *av_set, void *context)
{
#if 0
	struct sharp_mc *mc;
	struct sharp_ep *ep;
	ep = container_of(fid, struct sharp_ep, util_ep.ep_fid.fid);

	mc = calloc(1, sizeof(*mc));
	if (!mc)
		return NULL;

	mc->mc_fid.fid.fclass = FI_CLASS_MC;
	mc->mc_fid.fid.context = context;
	mc->mc_fid.fid.ops = &sharp_mc_ops;
	mc->mc_fid.fi_addr = (uintptr_t) mc;

	ofi_atomic_inc32(&av_set->ref);
	mc->av_set = av_set;
	ofi_atomic_inc32(&ep->ref);
	mc->ep = ep;

	return mc;
#else
	return NULL;
#endif
}

/// @brief XXX to be combined w/ call_find_local_rank
static int sharp_find_local_rank(struct fid_ep *ep, struct sharp_mc *sharp_mc)
{
	struct sharp_av *av = container_of(sharp_mc->av_set->av, struct sharp_av,
					  util_av.av_fid);
	fi_addr_t my_addr;
	int i;

	my_addr = av->peer_av->owner_ops->ep_addr(av->peer_av, ep);

	sharp_mc->local_rank = FI_ADDR_NOTAVAIL;
	if (my_addr != FI_ADDR_NOTAVAIL) {
		for (i = 0; i < sharp_mc->av_set->fi_addr_count; i++)
			if (sharp_mc->av_set->fi_addr_array[i] == my_addr) {
				sharp_mc->local_rank = i;
				break;
			}
	}

	return FI_SUCCESS;
}

#endif

int sharp_join_collective(struct fid_ep *fid, const void *addr, uint64_t flags,
		    struct fid_mc **mc_fid, void *context)
{

#if 0
	struct fi_collective_addr *c_addr;

	struct sharp_mc *mc, *new_mc;

	struct util_av_set *av_set;

	fi_addr_t coll_addr;
	const struct fid_av_set *set;
	


	if (!(flags & FI_COLLECTIVE))
		return -FI_EBADFLAGS;
	
	c_addr = (struct fi_collective_addr *)addr;
	coll_addr = c_addr->coll_addr;
	set = c_addr->set;

	av_set = container_of(set, struct util_av_set, av_set_fid);

	if (coll_addr == FI_ADDR_NOTAVAIL) {
		assert(av_set->av->av_set);
		mc = &av_set->av->av_set->coll_mc;
	} else {
		mc = (struct sharp_mc*) ((uintptr_t) coll_addr);
	}

	new_mc = sharp_mc_create(fid, av_set, context);
	if (!new_mc)
		return -FI_ENOMEM;
	
	/* get the rank */
	sharp_find_local_rank(fid, new_mc);
	sharp_find_local_rank(fid, mc);

	//XXX map to sharp_coll_comm_init()

	*mc_fid = &new_mc->mc_fid;

	return 0; //XXX
#else
	return -FI_ENOSYS;
#endif
}


