/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2017 NXP
 *
 *  Ruchika Gupta <ruchika.gupta@nxp.com>
 */

#ifndef __JOBDESC_H
#define __JOBDESC_H

#include <stdint.h>

#define KEY_BLOB_SIZE 32
#define MAC_SIZE 16

#define KEY_IDNFR_SZ_BYTES 16
#define CLASS_SHIFT 25
#define CLASS_2 (0x02 << CLASS_SHIFT)

#define CMD_SHIFT 27
#define CMD_OPERATION (0x10 << CMD_SHIFT)

#define OP_TYPE_SHIFT 24
#define OP_TYPE_ENCAP_PROTOCOL (0x07 << OP_TYPE_SHIFT)

/* Assuming OP_TYPE = OP_TYPE_UNI_PROTOCOL */
#define OP_PCLID_SHIFT 16
#define OP_PCLID_BLOB (0x0d << OP_PCLID_SHIFT)

#define BLOB_PROTO_INFO 0x00000002

uint32_t desc_length(uint32_t *desc);
void desc_init(uint32_t *desc);
void desc_update_start_index(uint32_t *desc, uint32_t index);
void desc_add_word(uint32_t *desc, uint32_t word);
void desc_add_ptr(uint32_t *desc, phys_addr_t *ptr);


int cnstr_rng_jobdesc(uint32_t *desc, uint32_t state_handle,
		      uint32_t *add_inp, uint32_t add_ip_len,
		      uint8_t *out_data, uint32_t len);

int cnstr_rng_instantiate_jobdesc(uint32_t *desc);

// Construct descriptor to generate hw key blob
int cnstr_hw_encap_blob_jobdesc(uint32_t *desc, uint8_t *key_idnfr,
				uint32_t key_sz, uint32_t key_class,
				uint8_t *plain_txt, uint32_t in_sz,
				uint8_t *enc_blob, uint32_t out_sz,
				uint32_t operation);

#endif
