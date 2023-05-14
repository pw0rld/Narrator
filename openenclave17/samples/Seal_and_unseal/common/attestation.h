// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H
#define OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H

#include <openenclave/enclave.h>
#include "crypto.h"

#define ENCLAVE_SECRET_DATA_SIZE 16
#define PRINT_ATTESTATION_MESSAGES 0

class Attestation
{
private:
  Crypto *m_crypto;
  uint8_t *m_enclave_signer_id;
  uint8_t other_signer_id[32] = {0x35,
                                 0xf2,
                                 0xfe,
                                 0x66,
                                 0xb1,
                                 0xba,
                                 0x15,
                                 0x1e,
                                 0x38,
                                 0x9e,
                                 0x15,
                                 0x61,
                                 0x38,
                                 0x9c,
                                 0x95,
                                 0x2,
                                 0xb1,
                                 0x25,
                                 0xda,
                                 0x33,
                                 0x2c,
                                 0x5e,
                                 0xfa,
                                 0xb6,
                                 0xfa,
                                 0xfc,
                                 0x69,
                                 0x44,
                                 0xea,
                                 0x84,
                                 0xde,
                                 0x15}; //SE signer id

public:
  Attestation(Crypto *crypto, uint8_t *enclave_signer_id);

  // Get format settings.
  bool get_format_settings(
      const oe_uuid_t *format_id,
      uint8_t **format_settings_buffer,
      size_t *format_settings_buffer_size);

  // Generate evidence for the given data.
  bool generate_attestation_evidence(
      const oe_uuid_t *format_id,
      uint8_t *format_settings,
      size_t format_settings_size,
      const uint8_t *data,
      size_t data_size,
      uint8_t **evidence,
      size_t *evidence_size);

  /**
     * Attest the given evidence and accompanying data. The evidence
     * is first attested using the oe_verify_evidence API. This ensures the
     * authenticity of the enclave that generated the evidence. Next the enclave
     * signer_id and unique_id values are tested to establish trust of the
     * enclave that generated the evidence.
     */
  bool attest_attestation_evidence(
      const oe_uuid_t *format_id,
      const uint8_t *evidence,
      size_t evidence_size,
      const uint8_t *data,
      size_t data_size);
};

#endif // OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H
