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
	ofi_atomic_dec32(&mc->av_set->ref);
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

struct sharp_coll_mc {
	struct fid_mc		mc_fid;
	struct util_av_set	*av_set;
	uint64_t		local_rank;
	uint16_t		group_id;
	uint16_t		seq;
	ofi_atomic32_t		ref;
	struct fid_mc		*peer_mc;
	void 			*context; /* SHARP COLL context */
};

static struct sharp_coll_mc *sharp_create_mc(struct util_av_set *av_set,
					   void *context)
{
	struct sharp_coll_mc *coll_mc;

	coll_mc = calloc(1, sizeof(*coll_mc));
	if (!coll_mc)
		return NULL;

	coll_mc->mc_fid.fid.fclass = FI_CLASS_MC;
	coll_mc->mc_fid.fid.context = context;
	coll_mc->mc_fid.fid.ops = &sharp_mc_fid_ops;
	coll_mc->mc_fid.fi_addr = (uintptr_t) coll_mc;

	ofi_atomic_inc32(&av_set->ref);
	coll_mc->av_set = av_set;

	return coll_mc;
}

static void sharp_progress_work(struct util_ep *util_ep,
				struct util_coll_operation *coll_op)
{
	struct util_coll_work_item *next_ready = NULL;
	struct util_coll_work_item *cur_item = NULL;
	struct util_coll_work_item *prev_item = NULL;
	struct dlist_entry *tmp = NULL;
	int previous_is_head;

	/* clean up any completed items while searching for the next ready */
	dlist_foreach_container_safe(&coll_op->work_queue,
				     struct util_coll_work_item,
				     cur_item, waiting_entry, tmp) {

		previous_is_head = (cur_item->waiting_entry.prev ==
				    &cur_item->coll_op->work_queue);
		if (!previous_is_head) {
			prev_item = container_of(cur_item->waiting_entry.prev,
						 struct util_coll_work_item,
						 waiting_entry);
		}

		if (cur_item->state == UTIL_COLL_COMPLETE) {
			/*
			 * If there is work before cur and cur is fencing,
			 * we can't complete.
			 */
			if (cur_item->fence && !previous_is_head)
				continue;

			FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
			       "Removing Completed Work item: %p \n", cur_item);
			dlist_remove(&cur_item->waiting_entry);
			free(cur_item);

			/* if the work queue is empty, we're done */
			if (dlist_empty(&coll_op->work_queue)) {
				free(coll_op);
				return;
			}
			continue;
		}

		/* we can't progress if prior work is fencing */
		if (!previous_is_head && prev_item && prev_item->fence) {
			FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
			       "%p fenced by: %p \n", cur_item, prev_item);
			return;
		}

		/*
		 * If the current item isn't waiting, it's not the next
		 * ready item.
		 */
		if (cur_item->state != UTIL_COLL_WAITING) {
			FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
			       "Work item not waiting: %p [%s]\n", cur_item,
			       log_util_coll_state[cur_item->state]);
			continue;
		}

		FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
		       "Ready item: %p \n", cur_item);
		next_ready = cur_item;
		break;
	}

	if (!next_ready)
		return;

	//XXcoll_log_work(coll_op);

	next_ready->state = UTIL_COLL_PROCESSING;
	slist_insert_tail(&next_ready->ready_entry, &util_ep->coll_ready_queue);
}

void sharp_ep_progress(struct util_ep *util_ep)
{
	struct util_coll_work_item *work_item;
	struct util_coll_operation *coll_op;

	while (!slist_empty(&util_ep->coll_ready_queue)) {
		slist_remove_head_container(&util_ep->coll_ready_queue,
					    struct util_coll_work_item,
					    work_item, ready_entry);
		coll_op = work_item->coll_op;
		switch (work_item->type) {
		case UTIL_COLL_COMP:
			if (work_item->coll_op->comp_fn)
				work_item->coll_op->comp_fn(work_item->coll_op);

			work_item->state = UTIL_COLL_COMPLETE;
			break;

		default:
			goto out;
		}

		sharp_progress_work(util_ep, coll_op);
	}

out:
	return;

}

static struct util_coll_operation *
sharp_create_op(struct fid_ep *ep, struct sharp_coll_mc *coll_mc,
	       enum util_coll_op_type type, uint64_t flags,
	       void *context, util_coll_comp_fn_t comp_fn)
{
	struct util_coll_operation *coll_op;

	coll_op = calloc(1, sizeof(*coll_op));
	if (!coll_op)
		return NULL;

	coll_op->ep = ep;
	coll_op->cid = 1; //XXX coll_get_next_id(coll_mc);
	coll_op->mc = (struct util_coll_mc*) coll_mc;
	coll_op->type = type;
	coll_op->flags = flags;
	coll_op->context = context;
	coll_op->comp_fn = comp_fn;
	dlist_init(&coll_op->work_queue);

	return coll_op;
}

static void sharp_join_comp(struct util_coll_operation *coll_op)
{
	struct fi_eq_entry entry;
	struct sharp_ep *ep;
	struct ofi_coll_eq *eq;
	uint64_t flags;

	ep = container_of(coll_op->ep, struct sharp_ep, util_ep.ep_fid);
	eq = container_of(ep->util_ep.eq, struct ofi_coll_eq, util_eq.eq_fid);

	coll_op->data.join.new_mc->seq = 0;
	coll_op->data.join.new_mc->group_id =
		(uint16_t) ofi_bitmask_get_lsbset(coll_op->data.join.data);

	/* mark the local mask bit */
	ofi_bitmask_unset(ep->util_ep.coll_cid_mask,
			  coll_op->data.join.new_mc->group_id);

	/* write to the eq */
	memset(&entry, 0, sizeof(entry));
	entry.fid = &coll_op->mc->mc_fid.fid;
	entry.context = coll_op->context;

	flags = FI_COLLECTIVE;
	if (coll_op->mc->peer_mc)
		flags |= FI_PEER;
	if (fi_eq_write(eq->peer_eq, FI_JOIN_COMPLETE, &entry,
			sizeof(struct fi_eq_entry), flags) < 0)
		FI_WARN(ep->util_ep.domain->fabric->prov, FI_LOG_DOMAIN,
			"join collective - eq write failed\n");

	ofi_bitmask_free(&coll_op->data.join.data);
	ofi_bitmask_free(&coll_op->data.join.tmp);
}

/* XXX to be replaced with ofi_coll_find_local_rank implementation*/
int coll_find_local_rank(struct fid_ep *ep, struct util_coll_mc *coll_mc);

/* reused from coll_bind_work */
static void sharp_bind_work(struct util_coll_operation *coll_op,
			   struct util_coll_work_item *item)
{
	item->coll_op = coll_op;
	dlist_insert_tail(&item->waiting_entry, &coll_op->work_queue);
}

/* reused from coll_sched_comp */
static int sharp_sched_comp(struct util_coll_operation *coll_op)
{
	struct util_coll_work_item *comp_item;

	comp_item = calloc(1, sizeof(*comp_item));
	if (!comp_item)
		return -FI_ENOMEM;

	comp_item->type = UTIL_COLL_COMP;
	comp_item->state = UTIL_COLL_WAITING;
	comp_item->fence = 1;

	sharp_bind_work(coll_op, comp_item);
	return FI_SUCCESS;
}

int sharp_join_collective(struct fid_ep *ep, const void *addr,
		         uint64_t flags, struct fid_mc **mc, void *context)
{
	struct fi_peer_mc_context *peer_context;
	struct sharp_coll_mc *new_coll_mc;
	struct util_av_set *av_set;
	struct sharp_coll_mc *coll_mc;
	struct util_coll_operation *join_op;
	struct util_ep *util_ep;
	struct fi_collective_addr *c_addr;
	fi_addr_t coll_addr;
	const struct fid_av_set *set;
	int ret;

	if (!(flags & FI_COLLECTIVE))
		return -FI_ENOSYS;

	if (flags & FI_PEER) {
		peer_context = context;
		context = peer_context->mc_fid;
	}

	c_addr = (struct fi_collective_addr *)addr;
	coll_addr = c_addr->coll_addr;
	set = c_addr->set;

	av_set = container_of(set, struct util_av_set, av_set_fid);

	if (coll_addr == FI_ADDR_NOTAVAIL) {
		assert(av_set->av->av_set);
		coll_mc = (struct sharp_coll_mc *) &av_set->av->av_set->coll_mc;
	} else {
		coll_mc = (struct sharp_coll_mc*) ((uintptr_t) coll_addr);
	}

	new_coll_mc = sharp_create_mc(av_set, context);
	if (!new_coll_mc)
		return -FI_ENOMEM;

	if (flags & FI_PEER)
		new_coll_mc->peer_mc = context;

	/* get the rank */
	coll_find_local_rank(ep, (struct util_coll_mc *)new_coll_mc);
	coll_find_local_rank(ep, (struct util_coll_mc *)coll_mc);

	join_op = sharp_create_op(ep, new_coll_mc, UTIL_COLL_JOIN_OP, flags,
				 context, sharp_join_comp);
	if (!join_op) {
		ret = -FI_ENOMEM;
		goto err1;
	}

	join_op->data.join.new_mc = (struct util_coll_mc*)new_coll_mc;

	ret = ofi_bitmask_create(&join_op->data.join.data, OFI_MAX_GROUP_ID);
	if (ret)
		goto err2;

	ret = ofi_bitmask_create(&join_op->data.join.tmp, OFI_MAX_GROUP_ID);
	if (ret)
		goto err3;

	util_ep = container_of(ep, struct util_ep, ep_fid);

	ret = sharp_sched_comp(join_op);
	if (ret)
		goto err4;

	sharp_progress_work(util_ep, join_op);

	*mc = &new_coll_mc->mc_fid;
	return FI_SUCCESS;

err4:
	ofi_bitmask_free(&join_op->data.join.tmp);
err3:
	ofi_bitmask_free(&join_op->data.join.data);
err2:
	free(join_op);
err1:
	fi_close(&new_coll_mc->mc_fid.fid);
	return ret;
}

#if 0
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
#endif

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