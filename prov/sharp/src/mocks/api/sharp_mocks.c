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
#include <rdma/fi_errno.h>
#include <string.h>

#include "./sharp.h"

/* mock of struct sharp_coll_context */
struct sharp_coll_context {
	struct sharp_coll_init_spec mock_content;
};

/**
 * @brief SHARP coll context initialization
 *
 * This routine is initialize SHARP coll library and create @ref sharp_coll_context "SHARP coll context".
 * This is a collective, called from all processes of the job.
 *
 * @warning An application cannot call any SHARP coll routine before sharp_coll_init
 *
 * @param [in]  sharp_coll_spec         SHARP coll specification descriptor.
 * @param [out] sharp_coll_context      Initialized @ref sharp_coll_context "SHARP coll context".
 *
 * @return Error code as defined by @ref sharp_error_no
 */
int sharp_coll_init(struct sharp_coll_init_spec *sharp_coll_spec,
                    struct sharp_coll_context **sharp_coll_context)
{
	struct sharp_coll_context *context;
	context = calloc(1, sizeof(*context));
	if (!context)
		return -FI_ENOMEM;

	memcpy(&context->mock_content, sharp_coll_spec, sizeof(context->mock_content));

	*sharp_coll_context = context;

	return 0;
}

/**
 * @brief SHARP coll context finalize
 *
 * This routine finalizes and releases the resources associated with
 * @ref sharp_coll_context "SHARP coll context". typically done once, just before the process ends.
 *
 * @warning An application cannot call any SHARP coll routine after sharp_coll_finalize
 *
 * @param [in] context  SHARP coll context to cleanup.
 *
 * @return Error code as defined by @ref sharp_error_no
 */
int sharp_coll_finalize(struct sharp_coll_context *context)
{
	free(context);

	return 0;
}
