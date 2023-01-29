/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TEE_CLIENT_API_EXTENSIONS_H
#define TEE_CLIENT_API_EXTENSIONS_H

#include <tee_client_api.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef TEEC_Result (*TEEC_GenericRpcCallback)(int, void *, size_t, void *, size_t, void *, size_t, void *);

/**
 * TEEC_RegisterMemoryFileDescriptor() - Register a block of existing memory as
 * a shared block within the scope of the specified context.
 *
 * @param context    The initialized TEE context structure in which scope to
 *                   open the session.
 * @param sharedMem  pointer to the shared memory structure to register.
 * @param fd         file descriptor of the target memory.
 *
 * @return TEEC_SUCCESS              The registration was successful.
 * @return TEEC_ERROR_OUT_OF_MEMORY  Memory exhaustion.
 * @return TEEC_Result               Something failed.
 */
TEEC_Result TEEC_RegisterSharedMemoryFileDescriptor(TEEC_Context *context,
						    TEEC_SharedMemory *sharedMem,
						    int fd);

/**
 * TEEC_ReceiveReplyGenericRpc() - Executes a loop that receives, parses and
 * replies to Generic RPC requests. For each Generic RPC request, it invokes
 * the function supplied.
 *
 * @param session    A handle to an open connection to the trusted application.
 * @param callback   Pointer to a function that handles an individual Generic
 *                   RPC.
 * @param context    An optional pointer to data to be passed to the RPC
 *                   callback function.
 *
 * @return TEEC_SUCCESS              The registration was successful.
 * @return TEEC_ERROR_BAD_PARAMETERS At least one of the parameters is NULL.
 * @return TEEC_ERROR_OUT_OF_MEMORY  Memory exhaustion.
 * @return TEEC_Result               Something failed.
 */
TEEC_Result TEEC_ReceiveReplyGenericRpc(TEEC_Session *session,
					TEEC_GenericRpcCallback callback,
					void *context);

#ifdef __cplusplus
}
#endif

#endif /* TEE_CLIENT_API_EXTENSIONS_H */
