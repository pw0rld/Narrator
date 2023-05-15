#include "sys_tpm_counter.h"
extern "C" {
#include "tpm_session_test/sys-context-util.h"
}

#include "easylogging++.h"

TSS2_RC rc;    
TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
TSS2_SYS_CONTEXT *sys_ctx = NULL;

int sys_init() {
    rc = 0;
    tcti_ctx = tcti_device_init("/dev/tpmrm0");
    sys_ctx = sys_init_from_tcti_ctx(tcti_ctx);
    return TSS2_RC_SUCCESS;
}

int define_nv_test(uint32_t nv_handle) {
    TPM2B_AUTH nv_auth = {.size = 0, .buffer = {}};
    TPM2B_NV_PUBLIC nv_public = {
        .size = 0,
        .nvPublic = {
            .nvIndex = nv_handle,
            .nameAlg = TPM2_ALG_SHA256,
            .attributes =
                (TPMA_NV_OWNERWRITE | TPMA_NV_ORDERLY | TPMA_NV_OWNERREAD | 
                TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT),
            .authPolicy = {.size = 0, .buffer = {}},
            .dataSize = 8,
    }};
    TSS2L_SYS_AUTH_RESPONSE rsp_auth = { 0 };
    TSS2L_SYS_AUTH_COMMAND cmd_auth = {
        .count = 1,
        .auths = {{
            .sessionHandle = TPM2_RS_PW,       
        }},
    };
    cmd_auth.auths[0].hmac.size = 0;
    rc = Tss2_Sys_NV_DefineSpace(sys_ctx, TPM2_RH_OWNER, &cmd_auth,
                                 &nv_auth, &nv_public, &rsp_auth);
    if (rc != 0) {
        LOG(ERROR) << " Tss2_Sys_NV_DefineSpace failed. " << Tss2_RC_Decode(rc);
        return -1;
    }
    return 0;
}

int increment_nv_test(uint32_t nv_handle) {
    TPM2B_AUTH nv_auth = {.size = 0, .buffer = {}};
    TSS2L_SYS_AUTH_RESPONSE rsp_auth = { 0 };
    TSS2L_SYS_AUTH_COMMAND cmd_auth = {
        .count = 1,
        .auths = {{
            .sessionHandle = TPM2_RS_PW,       
        }},
    };
    cmd_auth.auths[0].hmac.size = 0;
    rc = Tss2_Sys_NV_Increment(sys_ctx, TPM2_RH_OWNER, nv_handle, &cmd_auth, &rsp_auth);
    if (rc != 0) {
        LOG(ERROR) << " Tss2_Sys_NV_Increment failed. " << Tss2_RC_Decode(rc);
        return -1;
    }
    return 0;
}