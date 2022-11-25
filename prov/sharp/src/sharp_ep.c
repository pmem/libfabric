/*
 * Copyright (c) 2022 Intel Corporation. All rights reserved
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
#include <sys/uio.h>
#include <sys/un.h>

#include "ofi_iov.h"
#include "ofi_mr.h"

#include "sharp.h"

static int sharp_getname(fid_t fid, void *addr, size_t *addrlen)
{
	int ret;
	struct sharp_ep *ep;
	char *name = addr;

	ep = container_of(fid, struct sharp_ep, util_ep.ep_fid.fid);

	if (!name || *addrlen == 0 ||
	    snprintf(name, *addrlen, "sharp ") >= *addrlen)
		return -FI_ETOOSMALL;
	
	*addrlen -= 6;
	name +=6;
    ret = fi_getname(&ep->peer_ep->fid, name, addrlen);

	if (!ret)
		*addrlen -= 6;

	return ret;
}

static struct fi_ops_cm sharp_ep_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = fi_no_setname,
	.getname = sharp_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect, //XXX
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
	.join = sharp_join_collective,
};

static int sharp_ep_close(struct fid *fid)
{
	struct sharp_ep *ep;

	ep = container_of(fid, struct sharp_ep, util_ep.ep_fid.fid);

	ofi_endpoint_close(&ep->util_ep);
	ofi_spin_destroy(&ep->lock);

	free(ep);
	return 0;
}

static int sharp_ep_bind_cq(struct sharp_ep *ep, struct util_cq *cq, uint64_t flags)
{
	int ret;
//XXX
	ret = ofi_ep_bind_cq(&ep->util_ep, cq, flags);
	if (ret)
		return ret;

	ret = fid_list_insert(&cq->ep_list,
			      &cq->ep_list_lock,
			      &ep->util_ep.ep_fid.fid);

	return ret;
}

static int sharp_ep_bind(struct fid *ep_fid, struct fid *bfid, uint64_t flags)
{
	struct sharp_ep *ep;
	struct util_av *av;
	int ret;

	ep = container_of(ep_fid, struct sharp_ep, util_ep.ep_fid.fid);
	switch (bfid->fclass) {
	case FI_CLASS_AV:
		av = container_of(bfid, struct util_av, av_fid.fid);
		ret = ofi_ep_bind_av(&ep->util_ep, av);
		if (ret) {
			FI_WARN(&sharp_prov, FI_LOG_EP_CTRL,
				"duplicate AV binding\n");
			return -FI_EINVAL;
		}
		break;
	case FI_CLASS_CQ:
		ret = sharp_ep_bind_cq(ep, container_of(bfid, struct util_cq,
						      cq_fid.fid), flags);
		break;
	case FI_CLASS_EQ:
	case FI_CLASS_CNTR:
	case FI_CLASS_SRX_CTX:
	default:
		FI_WARN(&sharp_prov, FI_LOG_EP_CTRL,
			"invalid fid class\n");
		ret = -FI_EINVAL;
		break;
	}
	return ret;
}

static int sharp_ep_ctrl(struct fid *fid, int command, void *arg)
{
#if 0
	struct sharp_ep *ep;
	ep = container_of(fid, struct sharp_ep, util_ep.ep_fid.fid);
#endif

	switch (command) {
	case FI_ENABLE:
		return -FI_ENOSYS;
		break;
	default:
		return -FI_ENOSYS;
	}
	return -FI_ENOSYS;
}

static struct fi_ops sharp_ep_fid_ops = {
	.size = sizeof(struct fi_ops),
	.close = sharp_ep_close,
	.bind = sharp_ep_bind,
	.control = sharp_ep_ctrl,
	.ops_open = fi_no_ops_open,
};

static ssize_t sharp_ep_barrier(struct fid_ep *ep, fi_addr_t coll_addr,
		       void *context)
{
	return -FI_ENOSYS;

}

static ssize_t 
sharp_ep_allreduce(struct fid_ep *ep, const void *buf, size_t count, void *desc,
		 void *result, void *result_desc, fi_addr_t coll_addr,
		 enum fi_datatype datatype, enum fi_op op, uint64_t flags,
		 void *context)
{
	return -FI_ENOSYS;
}

static struct fi_ops_collective sharp_ep_collective_ops = {
	.size = sizeof(struct fi_ops_collective),
	.barrier = sharp_ep_barrier,
	.broadcast = fi_coll_no_broadcast,
	.alltoall = fi_coll_no_alltoall,
	.allreduce = sharp_ep_allreduce,
	.allgather = fi_coll_no_allgather,
	.reduce_scatter = fi_coll_no_reduce_scatter,
	.reduce = fi_coll_no_reduce,
	.scatter = fi_coll_no_scatter,
	.gather = fi_coll_no_gather,
	.msg = fi_coll_no_msg,
};
static struct fi_ops_ep sharp_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = fi_no_cancel, //XXX
	.getopt = fi_no_getopt,
	.setopt = fi_no_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

inline static void
fid_ep_init(struct fid_ep **ep_fid, 
		struct util_ep *util_ep, struct fi_ops *fid_ops, 
		struct fi_ops_ep *ops, struct fi_ops_cm *cm,
		struct fi_ops_msg *msg, struct fi_ops_rma	*rma,
		struct fi_ops_tagged *tagged, struct fi_ops_atomic *atomic,
		struct fi_ops_collective *collective)
{
	*ep_fid = &util_ep->ep_fid;
	(*ep_fid)->fid.ops = fid_ops;
	(*ep_fid)->ops = ops;
	(*ep_fid)->cm = cm;
	(*ep_fid)->msg = msg;
	(*ep_fid)->rma = rma;
	(*ep_fid)->tagged = tagged;
	(*ep_fid)->atomic = atomic;
	(*ep_fid)->collective = collective;
}

int sharp_endpoint(struct fid_domain *domain, struct fi_info *info,
		  struct fid_ep **ep_fid, void *context)
{
	struct sharp_ep *ep;
	struct fi_peer_transfer_context *peer_context = context;
	int ret;

	if (!info || !(info->mode & FI_PEER_TRANSFER)) {
		FI_WARN(&sharp_prov, FI_LOG_CORE,
			"FI_PEER_TRANSFER mode required\n");
		return -EINVAL;
	}

	ep = calloc(1, sizeof(*ep));
	if (!ep)
		return -FI_ENOMEM;

	ofi_atomic_initialize32(&ep->ref, 0);

	ret = ofi_spin_init(&ep->lock);
	if (ret)
		goto error_ep;

	ep->peer_ep = peer_context->ep;
	ret = ofi_endpoint_init(domain, &sharp_util_prov, info, &ep->util_ep, context,
				sharp_ep_progress);
	if (ret)
		goto error_lock;

	fid_ep_init(ep_fid, &ep->util_ep, &sharp_ep_fid_ops, &sharp_ep_ops,
		&sharp_ep_cm_ops, NULL, NULL, NULL, NULL, &sharp_ep_collective_ops);

	return 0;

error_lock:
	ofi_spin_destroy(&ep->lock);
error_ep:
	free(ep);
	return ret;
}


