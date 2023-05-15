#ifndef SYS_TPM_COUNTER_H
#define SYS_TPM_COUNTER_H

#include <tss2_common.h>
#include <tss2_esys.h>
#include <tss2_sys.h>
#include <tss2_mu.h>
#include <tss2_rc.h>
#include <tss2_tpm2_types.h>
#include <string>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


int sys_init();
int define_nv_test(uint32_t nv_handle);
int increment_nv_test(uint32_t nv_handle);










#endif //- SYS_TPM_COUNTER_H