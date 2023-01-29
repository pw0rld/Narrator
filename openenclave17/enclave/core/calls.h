// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>

#ifndef OE_CALLS_H
#define OE_CALLS_H

/**
 * The oe_ecalls_table table is expected to be generated by oeedger8r
 */
extern const oe_ecall_func_t oe_ecalls_table[];
extern const size_t oe_ecalls_table_size;

typedef struct _ecall_table
{
    const oe_ecall_func_t* ecalls;
    size_t num_ecalls;
} ecall_table_t;

#endif /* OE_CALLS_H */