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

#include "ofi_coll.h"
#include "../../coll/src/coll.h" // coll_ep, coll_eq

#include "sharp.h"

int sharp_query_collective(struct fid_domain *domain,
		enum fi_collective_op coll, struct fi_collective_attr *attr,
		uint64_t flags)
{
	if (!attr || attr->mode != 0)
		return -FI_EINVAL;

	switch (coll) {
	case FI_BARRIER:
		return FI_SUCCESS; /* XXX to be integrated w/ sharp_query */
	case FI_ALLREDUCE:
		return FI_SUCCESS; /* XXX to be integrated w/ sharp_query */
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
#if 0
	/* XXX to be enabled with real implementation of fi_join */
	ofi_atomic_dec32(&mc->av_set->ref); 
#endif
	free(mc);
	return 0;
}

static struct fi_ops sharp_mc_fid_ops = {
	.size = sizeof(struct fi_ops),
	.close = sharp_mc_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};


int sharp_join_collective(struct fid_ep *fid, const void *addr, uint64_t flags,
			  struct fid_mc **mc_fid, void *context)
{
	struct fi_peer_mc_context *peer_context;
	struct sharp_mc *mc;

	if (!(flags & FI_COLLECTIVE))
		return -FI_ENOSYS;

	if ((flags & FI_PEER)) {
		peer_context = context;
		context = peer_context->mc_fid;
	}

	mc = calloc(1, sizeof(*mc));
	if (!mc)
		return -FI_ENOMEM;

	*mc_fid = &mc->mc_fid;
	(*mc_fid)->fid.ops = &sharp_mc_fid_ops;
	if ((flags & FI_PEER))
		mc->peer_mc = context;
	mc->mc_fid.fi_addr = (uintptr_t)mc;

	/* XXX Dummy implementation */
	struct fi_eq_entry entry;
	struct sharp_ep *ep;
	struct ofi_coll_eq *eq;
	int ret;

	ep = container_of(fid, struct sharp_ep, util_ep.ep_fid);
	eq = container_of(ep->util_ep.eq, struct ofi_coll_eq, util_eq.eq_fid);
	/* write to the eq */
	memset(&entry, 0, sizeof(entry));
	entry.fid = &((*mc_fid)->fid);
	entry.context = context;

	flags = FI_COLLECTIVE;
	if (mc->peer_mc)
		flags |= FI_PEER;
	ret = fi_eq_write(eq->peer_eq, FI_JOIN_COMPLETE, &entry,
			sizeof(struct fi_eq_entry), flags);
	if (ret <= 0) {
		FI_WARN(ep->util_ep.domain->fabric->prov, FI_LOG_EQ,
			"join collective - fi_eq_write() failed\n");
		return ret;
	}
	return FI_SUCCESS;
}

ssize_t sharp_ep_barrier2(struct fid_ep *fid, fi_addr_t coll_addr, 
				uint64_t flags, void *context)
{
#if 1
	/* XXX Dummy implementation based on peer:fi_barrier() */
	struct sharp_ep *ep;
	struct sharp_mc *sharp_mc;
	ep = container_of(fid, struct sharp_ep, util_ep.ep_fid);
	sharp_mc = (struct sharp_mc *) ((uintptr_t) coll_addr);

	coll_addr = fi_mc_addr(sharp_mc->peer_mc);

	flags |= FI_PEER_TRANSFER;
	return fi_barrier2(ep->peer_ep, coll_addr, flags, context);
#else
	/* XXX Dummy implementation */

	struct sharp_ep *ep;
	struct ofi_coll_cq *cq;
	ssize_t ret;

	ep = container_of(fid, struct sharp_ep, util_ep.ep_fid);
	cq = container_of(ep->util_ep.tx_cq, struct ofi_coll_cq, util_cq);
	ret = cq->peer_cq->owner_ops->write(cq->peer_cq, context, FI_COLLECTIVE, 
						0, 0, 0, 0, 0);

	if (ret)
		FI_WARN(ep->util_ep.domain->fabric->prov, FI_LOG_CQ,
			"barrier2 - cq write failed\n");

	return ret;
#endif
}

ssize_t sharp_ep_barrier(struct fid_ep *ep, fi_addr_t coll_addr, void *context)
{
	return sharp_ep_barrier2(ep, coll_addr, 0, context);
}


ssize_t sharp_ep_allreduce(struct fid_ep *fid, const void *buf, size_t count,
			  void *desc, void *result, void *result_desc,
			  fi_addr_t coll_addr, enum fi_datatype datatype,
			  enum fi_op op, uint64_t flags, void *context)
{
#if 1
	/* XXX Dummy implementation based on peer:fi_allreduce() */
	struct sharp_ep *ep;
	struct sharp_mc *sharp_mc;
	ep = container_of(fid, struct sharp_ep, util_ep.ep_fid);
	sharp_mc = (struct sharp_mc *) ((uintptr_t) coll_addr);

	coll_addr = fi_mc_addr(sharp_mc->peer_mc);

	flags |= FI_PEER_TRANSFER;
	return fi_allreduce(ep->peer_ep, buf, count, desc, result,
		result_desc, coll_addr, datatype, op, flags, context);
#else
	/* XXX Dummy implementation */
	struct ofi_coll_cq *cq;
	ssize_t ret;

	memcpy(result,buf,count*ofi_datatype_size(datatype));
	struct sharp_ep *ep;
	struct ofi_coll_cq *cq;
	ssize_t ret;

	ep = container_of(fid, struct sharp_ep, util_ep.ep_fid);
	cq = container_of(ep->util_ep.tx_cq, struct ofi_coll_cq, util_cq);
	ret = cq->peer_cq->owner_ops->write(cq->peer_cq, context, FI_COLLECTIVE, 
						0, 0, 0, 0, 0);
	if (ret)
		FI_WARN(ep->util_ep.domain->fabric->prov, FI_LOG_CQ,
			"allreduce - cq write failed\n");
	memcpy(result,buf,count*ofi_datatype_size(datatype));
	return ret;
#endif
}

ssize_t sharp_peer_xfer_complete(struct fid_ep *ep_fid,
				struct fi_cq_tagged_entry *cqe,
				fi_addr_t src_addr)
{
	struct sharp_ep *ep;
	struct ofi_coll_cq *cq;

	ep = container_of(ep_fid, struct sharp_ep, util_ep.ep_fid);
	cq = container_of(ep->util_ep.tx_cq, struct ofi_coll_cq, util_cq);

	if (cq->peer_cq->owner_ops->write(cq->peer_cq, cqe->op_context,
					  FI_COLLECTIVE, 0, 0, 0, 0, 0))
		FI_WARN(ep->util_ep.domain->fabric->prov, FI_LOG_DOMAIN,
			"collective - cq write failed\n");
	return 0;
}

ssize_t sharp_peer_xfer_error(struct fid_ep *ep_fid, struct fi_cq_err_entry *cqerr)
{
	struct sharp_ep *ep;
	struct ofi_coll_cq *cq;

	ep = container_of(ep_fid, struct sharp_ep, util_ep.ep_fid);
	cq = container_of(ep->util_ep.tx_cq, struct ofi_coll_cq, util_cq);

	if (cq->peer_cq->owner_ops->writeerr(cq->peer_cq, cqerr))
		FI_WARN(ep->util_ep.domain->fabric->prov, FI_LOG_DOMAIN,
			"collective - cq write failed\n");
	return 0;
}