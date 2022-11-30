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
		return FI_SUCCESS; //XXX to be integrated w/ sharp_query
	case FI_ALLREDUCE:
		return FI_SUCCESS; //XXX to be integrated w/ sharp_query
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


int sharp_join_collective1(struct fid_ep *fid, const void *addr, uint64_t flags,
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

static uint32_t sharp_get_next_id(struct sharp_mc *sharp_mc)
{
	uint32_t cid = sharp_mc->group_id;
	return cid << 16 | sharp_mc->seq++;
}

static struct util_coll_operation *
sharp_create_op(struct fid_ep *ep, struct sharp_mc *sharp_mc,
	       enum util_coll_op_type type, uint64_t flags,
	       void *context, util_coll_comp_fn_t comp_fn)
{
	struct util_coll_operation *coll_op;

	coll_op = calloc(1, sizeof(*coll_op));
	if (!coll_op)
		return NULL;

	coll_op->ep = ep;
	coll_op->cid = sharp_get_next_id(sharp_mc);
	coll_op->mc = (struct util_coll_mc *)sharp_mc; //XXX
	coll_op->type = type;
	coll_op->flags = flags;
	coll_op->context = context;
	coll_op->comp_fn = comp_fn;
	dlist_init(&coll_op->work_queue);

	return coll_op;
}

static void sharp_log_work(struct util_coll_operation *coll_op)
{
#if ENABLE_DEBUG
	struct util_coll_work_item *cur_item = NULL;
	struct util_coll_xfer_item *xfer_item;
	struct dlist_entry *tmp = NULL;
	size_t count = 0;

	FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
	       "Remaining Work for %s:\n",
	       log_util_coll_op_type[coll_op->type]);
	dlist_foreach_container_safe(&coll_op->work_queue,
				     struct util_coll_work_item,
				     cur_item, waiting_entry, tmp)
	{
		switch (cur_item->type) {
		case UTIL_COLL_SEND:
			xfer_item = container_of(cur_item,
						 struct util_coll_xfer_item,
						 hdr);
			FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
			       "\t%ld: { %p [%s] SEND TO: 0x%02x FROM: 0x%02lx "
			       "cnt: %d typesize: %ld tag: 0x%02lx }\n",
			       count, cur_item,
			       log_util_coll_state[cur_item->state],
			       xfer_item->remote_rank, coll_op->mc->local_rank,
			       xfer_item->count,
			       ofi_datatype_size(xfer_item->datatype),
			       xfer_item->tag);
			break;

		case UTIL_COLL_RECV:
			xfer_item = container_of(cur_item,
						 struct util_coll_xfer_item,
						 hdr);
			FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
			       "\t%ld: { %p [%s] RECV FROM: 0x%02x TO: 0x%02lx "
			       "cnt: %d typesize: %ld tag: 0x%02lx }\n",
			       count, cur_item,
			       log_util_coll_state[cur_item->state],
			       xfer_item->remote_rank, coll_op->mc->local_rank,
			       xfer_item->count,
			       ofi_datatype_size(xfer_item->datatype),
			       xfer_item->tag);
			break;

		case UTIL_COLL_REDUCE:
			FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
			       "\t%ld: { %p [%s] REDUCTION }\n",
			       count, cur_item,
			       log_util_coll_state[cur_item->state]);
			break;

		case UTIL_COLL_COPY:
			FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
			       "\t%ld: { %p [%s] COPY }\n", count, cur_item,
			       log_util_coll_state[cur_item->state]);
			break;

		case UTIL_COLL_COMP:
			FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
			       "\t%ld: { %p [%s] COMPLETION }\n", count, cur_item,
			       log_util_coll_state[cur_item->state]);
			break;

		default:
			FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
			       "\t%ld: { %p [%s] UNKNOWN }\n", count, cur_item,
			       log_util_coll_state[cur_item->state]);
			break;
		}
		count++;
	}
#endif
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

	sharp_log_work(coll_op);

	next_ready->state = UTIL_COLL_PROCESSING;
	slist_insert_tail(&next_ready->ready_entry, &util_ep->coll_ready_queue);
}

static void sharp_bind_work(struct util_coll_operation *coll_op,
			   struct util_coll_work_item *item)
{
	item->coll_op = coll_op;
	dlist_insert_tail(&item->waiting_entry, &coll_op->work_queue);
}

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

static int sharp_find_local_rank(struct fid_ep *ep,
				struct sharp_mc *sharp_mc)
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

void sharp_join_comp(struct util_coll_operation *coll_op)
{
	struct fi_eq_entry entry;
	struct sharp_ep *ep;
	struct sharp_eq *eq;

	ep = container_of(coll_op->ep, struct sharp_ep, util_ep.ep_fid);
	eq = container_of(ep->util_ep.eq, struct sharp_eq, util_eq.eq_fid);

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

	if (fi_eq_write(eq->peer_eq, FI_JOIN_COMPLETE, &entry,
			sizeof(struct fi_eq_entry), FI_COLLECTIVE) < 0)
		FI_WARN(ep->util_ep.domain->fabric->prov, FI_LOG_DOMAIN,
			"join collective - eq write failed\n");

	ofi_bitmask_free(&coll_op->data.join.data);
	ofi_bitmask_free(&coll_op->data.join.tmp);
}

void sharp_collective_comp(struct util_coll_operation *coll_op)
{
	struct sharp_ep *ep;
	struct sharp_cq *cq;

	ep = container_of(coll_op->ep, struct sharp_ep, util_ep.ep_fid);
	cq = container_of(ep->util_ep.tx_cq, struct sharp_cq, util_cq);

	if (cq->peer_cq->owner_ops->write(cq->peer_cq, coll_op->context,
					  FI_COLLECTIVE, 0, 0, 0, 0, 0))
		FI_WARN(ep->util_ep.domain->fabric->prov, FI_LOG_DOMAIN,
			"collective - cq write failed\n");

	switch (coll_op->type) {
	case UTIL_COLL_ALLREDUCE_OP:
		free(coll_op->data.allreduce.data);
		break;

	case UTIL_COLL_SCATTER_OP:
		free(coll_op->data.scatter);
		break;

	case UTIL_COLL_BROADCAST_OP:
		free(coll_op->data.broadcast.chunk);
		free(coll_op->data.broadcast.scatter);
		break;

	case UTIL_COLL_JOIN_OP:
	case UTIL_COLL_BARRIER_OP:
	case UTIL_COLL_ALLGATHER_OP:
	default:
		/* nothing to clean up */
		break;
	}
}

static ssize_t sharp_process_reduce_item(struct util_coll_reduce_item *reduce_item)
{
	if (reduce_item->op < FI_MIN || reduce_item->op > FI_BXOR)
		return -FI_ENOSYS;

	ofi_atomic_write_handler(reduce_item->op, reduce_item->datatype,
				 reduce_item->inout_buf,
				 reduce_item->in_buf,
				 reduce_item->count);
	return FI_SUCCESS;
}

static ssize_t sharp_process_xfer_item(struct util_coll_xfer_item *item)
{
	struct util_coll_operation *coll_op;
	struct sharp_ep *ep;
	struct fi_msg_tagged msg;
	struct iovec iov;
	ssize_t ret;

	coll_op = item->hdr.coll_op;
	ep = container_of(coll_op->ep, struct sharp_ep, util_ep.ep_fid);

	msg.msg_iov = &iov;
	msg.desc = NULL;
	msg.iov_count = 1;
	msg.ignore = 0;
	msg.context = item;
	msg.data = 0;
	msg.tag = item->tag;
	msg.addr = coll_op->mc->av_set->fi_addr_array[item->remote_rank];

	iov.iov_base = item->buf;
	iov.iov_len = (item->count * ofi_datatype_size(item->datatype));

	if (item->hdr.type == UTIL_COLL_SEND) {
		ret = fi_tsendmsg(ep->peer_ep, &msg, FI_PEER_TRANSFER);
		if (!ret)
			FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
			       "%p SEND [0x%02lx] -> [0x%02x] cnt: %d sz: %ld\n",
			       item, coll_op->mc->local_rank, item->remote_rank,
			       item->count,
			       item->count * ofi_datatype_size(item->datatype));
		return ret;
	} else if (item->hdr.type == UTIL_COLL_RECV) {
		ret = fi_trecvmsg(ep->peer_ep, &msg, FI_PEER_TRANSFER);
		if (!ret)
			FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
			       "%p RECV [0x%02lx] <- [0x%02x] cnt: %d sz: %ld\n",
			       item, coll_op->mc->local_rank, item->remote_rank,
			       item->count,
			       item->count * ofi_datatype_size(item->datatype));
		return ret;
	}

	return -FI_ENOSYS;
}

void sharp_ep_progress(struct util_ep *util_ep)
{
	struct util_coll_work_item *work_item;
	struct util_coll_reduce_item *reduce_item;
	struct util_coll_copy_item *copy_item;
	struct util_coll_xfer_item *xfer_item;
	struct util_coll_operation *coll_op;
	ssize_t ret;

	while (!slist_empty(&util_ep->coll_ready_queue)) {
		slist_remove_head_container(&util_ep->coll_ready_queue,
					    struct util_coll_work_item,
					    work_item, ready_entry);
		coll_op = work_item->coll_op;
		switch (work_item->type) {
		case UTIL_COLL_SEND:
			xfer_item = container_of(work_item,
						 struct util_coll_xfer_item,
						 hdr);
			ret = sharp_process_xfer_item(xfer_item);
			if (ret && ret == -FI_EAGAIN) {
				slist_insert_tail(&work_item->ready_entry,
						  &util_ep->coll_ready_queue);
				goto out;
			}
			break;

		case UTIL_COLL_RECV:
			xfer_item = container_of(work_item,
						 struct util_coll_xfer_item,
						 hdr);
			ret = sharp_process_xfer_item(xfer_item);
			if (ret)
				goto out;
			break;

		case UTIL_COLL_REDUCE:
			reduce_item = container_of(work_item,
						   struct util_coll_reduce_item,
						   hdr);
			ret = sharp_process_reduce_item(reduce_item);
			if (ret)
				goto out;

			reduce_item->hdr.state = UTIL_COLL_COMPLETE;
			break;

		case UTIL_COLL_COPY:
			copy_item = container_of(work_item,
						 struct util_coll_copy_item,
						 hdr);
			memcpy(copy_item->out_buf, copy_item->in_buf,
			       copy_item->count *
				       ofi_datatype_size(copy_item->datatype));

			copy_item->hdr.state = UTIL_COLL_COMPLETE;
			break;

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

ssize_t sharp_peer_xfer_complete(struct fid_ep *ep,
				struct fi_cq_tagged_entry *cqe,
				fi_addr_t src_addr)
{
	struct util_coll_operation *coll_op;
	struct util_ep *util_ep;
	struct util_coll_xfer_item *xfer_item;

	xfer_item = cqe->op_context;
	xfer_item->hdr.state = UTIL_COLL_COMPLETE;

	coll_op = xfer_item->hdr.coll_op;
	FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
	       "\tXfer complete: { %p %s Remote: 0x%02x Local: "
	       "0x%02lx cnt: %d typesize: %ld }\n", xfer_item,
	       xfer_item->hdr.type == UTIL_COLL_SEND ? "SEND" : "RECV",
	       xfer_item->remote_rank, coll_op->mc->local_rank,
	       xfer_item->count, ofi_datatype_size(xfer_item->datatype));

	util_ep = container_of(coll_op->ep, struct util_ep, ep_fid);
	sharp_progress_work(util_ep, coll_op);

	return 0;
}

ssize_t sharp_peer_xfer_error(struct fid_ep *ep, struct fi_cq_err_entry *cqerr)
{
	struct util_coll_operation *coll_op;
	struct util_coll_xfer_item *xfer_item;

	xfer_item = cqerr->op_context;
	xfer_item->hdr.state = UTIL_COLL_COMPLETE;

	coll_op = xfer_item->hdr.coll_op;
	FI_DBG(coll_op->mc->av_set->av->prov, FI_LOG_CQ,
	       "\tXfer error: { %p %s Remote: 0x%02x Local: "
	       "0x%02lx cnt: %d typesize: %ld }\n", xfer_item,
	       xfer_item->hdr.type == UTIL_COLL_SEND ? "SEND" : "RECV",
	       xfer_item->remote_rank, coll_op->mc->local_rank,
	       xfer_item->count, ofi_datatype_size(xfer_item->datatype));

	/* TODO: finish the work with error */

	return 0;
}

static struct sharp_mc *sharp_create_mc(struct util_av_set *av_set,
					   void *context)
{
	struct sharp_mc *sharp_mc;

	sharp_mc = calloc(1, sizeof(*sharp_mc));
	if (!sharp_mc)
		return NULL;

	sharp_mc->mc_fid.fid.fclass = FI_CLASS_MC;
	sharp_mc->mc_fid.fid.context = context;
	sharp_mc->mc_fid.fid.ops = &sharp_mc_fid_ops;
	sharp_mc->mc_fid.fi_addr = (uintptr_t) sharp_mc;

	ofi_atomic_inc32(&av_set->ref);
	sharp_mc->av_set = av_set;

	return sharp_mc;
}

int sharp_join_collective(struct fid_ep *ep, const void *addr,
		         uint64_t flags, struct fid_mc **mc, void *context)
{
	struct sharp_mc *new_sharp_mc;
	struct util_av_set *av_set;
	struct sharp_mc *sharp_mc;
	struct util_coll_operation *join_op;
	struct util_ep *util_ep;
	struct sharp_ep *sharp_ep;
	struct fi_collective_addr *c_addr;
	fi_addr_t sharp_addr;
	const struct fid_av_set *set;
	struct fid_mc *util_mc;
	int ret;

	if (!(flags & FI_COLLECTIVE))
		return -FI_ENOSYS;

	util_ep = container_of(ep, struct util_ep, ep_fid);
	sharp_ep = container_of(ep, struct sharp_ep, util_ep.ep_fid);

	ret = fi_join(sharp_ep->peer_ep, addr, flags | FI_PEER, &util_mc, context);
	if (ret)
		return ret;

	c_addr = (struct fi_collective_addr *)addr;
	sharp_addr = c_addr->coll_addr;
	set = c_addr->set;

	av_set = container_of(set, struct util_av_set, av_set_fid);

	if (sharp_addr == FI_ADDR_NOTAVAIL) {
		assert(av_set->av->av_set);
		sharp_mc = (struct sharp_mc*) &av_set->av->av_set->coll_mc; //XXX
	} else {
		sharp_mc = (struct sharp_mc*) (struct util_coll_mc*) ((uintptr_t) sharp_addr); //XXX
	}

	new_sharp_mc = sharp_create_mc(av_set, context);
	if (!new_sharp_mc)
	{
		ret = FI_ENOMEM;
		goto err0;
	}

	/* get the rank */
	sharp_find_local_rank(ep, new_sharp_mc);
	sharp_find_local_rank(ep, sharp_mc);

	join_op = sharp_create_op(ep, sharp_mc, UTIL_COLL_JOIN_OP, flags,
				 context, sharp_join_comp);
	if (!join_op) {
		ret = -FI_ENOMEM;
		goto err1;
	}

	join_op->data.join.new_mc = (struct util_coll_mc *)new_sharp_mc; //XXX

	ret = ofi_bitmask_create(&join_op->data.join.data, OFI_MAX_GROUP_ID);
	if (ret)
		goto err2;

	ret = ofi_bitmask_create(&join_op->data.join.tmp, OFI_MAX_GROUP_ID);
	if (ret)
		goto err3;


#if 0 ///XXX
	ret = sharp_do_allreduce(join_op, util_ep->coll_cid_mask->bytes,
				join_op->data.join.data.bytes,
				join_op->data.join.tmp.bytes,
				(int) ofi_bitmask_bytesize(util_ep->coll_cid_mask),
				FI_UINT8, FI_BAND);
	if (ret)
		goto err4;
#endif ///XXX
	ret = sharp_sched_comp(join_op);
	if (ret)
		goto err4;

	sharp_progress_work(util_ep, join_op);

	*mc = &new_sharp_mc->mc_fid;
	new_sharp_mc->oob_fid_mc = util_mc;
	return FI_SUCCESS;

err4:
	ofi_bitmask_free(&join_op->data.join.tmp);
err3:
	ofi_bitmask_free(&join_op->data.join.data);
err2:
	free(join_op);
err1:
	fi_close(&new_sharp_mc->mc_fid.fid);
err0:
	fi_close(&util_mc->fid);
	return ret;
}

ssize_t sharp_ep_barrier2(struct fid_ep *ep, fi_addr_t coll_addr, uint64_t flags,
			 void *context)
{
	struct sharp_mc *sharp_mc;
	struct util_coll_operation *barrier_op;
	struct util_ep *util_ep;
	int ret;

	sharp_mc = (struct sharp_mc*) (struct util_coll_mc*) ((uintptr_t) coll_addr); //XXX

	barrier_op = sharp_create_op(ep, sharp_mc, UTIL_COLL_BARRIER_OP,
				    flags, context,
				    sharp_collective_comp);
	if (!barrier_op)
		return -FI_ENOMEM;

#if 0
	send = ~barrier_op->mc->local_rank;
	ret = coll_do_allreduce(barrier_op, &send,
				&barrier_op->data.barrier.data,
				&barrier_op->data.barrier.tmp, 1, FI_UINT64,
				FI_BAND);
	if (ret)
		goto err1;
#endif
	ret = sharp_sched_comp(barrier_op);
	if (ret)
		goto err1;

	util_ep = container_of(ep, struct util_ep, ep_fid);
	sharp_progress_work(util_ep, barrier_op);

	return FI_SUCCESS;
err1:
	free(barrier_op);
	return ret;

}

ssize_t sharp_ep_barrier(struct fid_ep *ep, fi_addr_t coll_addr, void *context)
{
	return sharp_ep_barrier2(ep, coll_addr, 0, context);
}


ssize_t sharp_ep_allreduce(struct fid_ep *ep, const void *buf, size_t count,
			  void *desc, void *result, void *result_desc,
			  fi_addr_t coll_addr, enum fi_datatype datatype,
			  enum fi_op op, uint64_t flags, void *context)
{
	struct sharp_mc *sharp_mc;
	struct util_coll_operation *allreduce_op;
	struct util_ep *util_ep;
	int ret;

	sharp_mc = (struct sharp_mc *) ((uintptr_t) coll_addr);
	allreduce_op = sharp_create_op(ep, sharp_mc, UTIL_COLL_ALLREDUCE_OP,
				      flags, context,
				      sharp_collective_comp);
	if (!allreduce_op)
		return -FI_ENOMEM;

	allreduce_op->data.allreduce.size = count * ofi_datatype_size(datatype);
	allreduce_op->data.allreduce.data = calloc(count,
						   ofi_datatype_size(datatype));
	if (!allreduce_op->data.allreduce.data) {
		ret = -FI_ENOMEM;
		goto err1;
	}

#if 0
	ret = coll_do_allreduce(allreduce_op, buf, result,
				allreduce_op->data.allreduce.data, count,
				datatype, op);
	if (ret)
		goto err2;
#else
	memcpy(result, buf, count * ofi_datatype_size(datatype));
#endif
	ret = sharp_sched_comp(allreduce_op);
	if (ret)
		goto err2;

	util_ep = container_of(ep, struct util_ep, ep_fid);
	sharp_progress_work(util_ep, allreduce_op);

	return FI_SUCCESS;

err2:
	free(allreduce_op->data.allreduce.data);
err1:
	free(allreduce_op);
	return ret;
}
