/*
    This file implements ocall related functions, while "tpm_counter.cpp" mainly
    implements tpm related functions.
*/
#include "tpm_counter.h"
#include "easylogging++.h"
extern "C" {
#include "tpm_session_test/sys-context-util.h"
}

//- These three headers are used in int_to_hex
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <thread>

extern int node_num;
// extern oe_enclave_t* enclave;
uint32_t ak_nv_index = 0x81010002;
// uint32_t ak_nv_index = 0x81010010;
ESYS_CONTEXT *tpm_ctx;
ESYS_TR ak_handler;

//- This init func shoud be called only once.
int initialize_tpm() {
    //- Init the context.
    int rc = Esys_Initialize(&tpm_ctx, NULL, NULL);
    if (rc != 0) {
        LOG(ERROR) << "Esys_Initialize failed";
        return -1;
    }
    //- Init the attestation key.
    // rc = Esys_TR_FromTPMPublic(tpm_ctx, ak_nv_index, ESYS_TR_NONE, ESYS_TR_NONE,
    //                         ESYS_TR_NONE, &ak_handler);
    // TPM2B_PUBLIC* key_info;
    // TPM2B_NAME* name;
    // TPM2B_NAME* qual_name;                            
    // rc = Esys_ReadPublic(tpm_ctx, ak_handler, ESYS_TR_NONE, ESYS_TR_NONE,
    //                         ESYS_TR_NONE, &key_info, &name, &qual_name);
    // if (rc != 0) {
    //     LOG(ERROR) << "Func: " << __FUNCTION__ << " Get ak_nv_index failed.";
    //     return -1;
    // }
    // LOG(INFO) << "padding = " << key_info->publicArea.parameters.rsaDetail.scheme.scheme;
    // LOG(INFO) << "exp = " << key_info->publicArea.parameters.rsaDetail.exponent;
    return 0;
}

template< typename T >
std::string int_to_hex( T i ) {
  std::stringstream stream;
  stream << "0x" 
         << std::setfill ('0') << std::setw(sizeof(T)*2) 
         << std::hex << i;
  return stream.str();
} 

void ocall_create_counter(uint32_t* counter_id) {
    //- For raft node 0, the nv handle varies from 0x01000000 to 0x01000FFF
    //- For raft node 1, the nv handle varies from 0x01001000 to 0x01001FFF
    uint32_t nv_first = 0x01000000 + (node_num * 0x00001000);
    uint32_t nv_last = nv_first + 0x00000FFF;
    uint32_t nv_handle = 0;
    for (nv_handle = nv_first; nv_handle <= nv_last; nv_handle++) {
        //- This nv handle is empty.
        if (is_nv_defined(nv_handle) == false) {
            break;
        }
    }
    if (nv_handle > nv_last) {
        LOG(ERROR) << "Func: " << __FUNCTION__ 
            << " There is no empty nv handle...";
        *counter_id = 0;
        return ;
    }
    *counter_id = nv_handle;
    LOG(INFO) << "Func: " << __FUNCTION__ << " Create a new nv counter, "
        << "handle = " << int_to_hex(*counter_id);
    return ;
}

void ocall_increase_counter(uint32_t counter_id) {
    TSS2_RC rc;
    ESYS_TR counter_handler = get_handler_by_counterID(counter_id, tpm_ctx);
    rc = Esys_NV_Increment(
        tpm_ctx, 
        ESYS_TR_RH_OWNER, 
        counter_handler,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE, 
        ESYS_TR_NONE);
    if (rc != 0) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " Esys_NV_Increment failed." 
            << " Error detail: " << Tss2_RC_Decode(rc);
    }
    return ;
}    

//- Use 256-bytes RSA public attestion key in TPM, so sig_data is always 256-bytes.
//- Note that RSA signature size corresponds to the RSA key size.
void ocall_retrieve_counter(uint32_t counter_id, uint8_t* qualification_data,
                            int qual_size, uint8_t* attested_data, 
                            int buffer_size, int* attest_size, uint8_t* sig_data) {
    TSS2_RC rc;
    TPM2B_ATTEST *certifyInfo = NULL;
    TPMT_SIGNATURE *signature = NULL;                                
    ESYS_TR counter_handler = get_handler_by_counterID(counter_id, tpm_ctx);

    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };
    //- Construct qualifying data.
    TPM2B_DATA qualifyingData;
    qualifyingData.size = qual_size;
    memcpy(qualifyingData.buffer, qualification_data, qual_size);

    rc = Esys_NV_Certify(
        tpm_ctx, 
        ak_handler, 
        ESYS_TR_RH_OWNER,
        counter_handler, 
        ESYS_TR_PASSWORD,
        ESYS_TR_PASSWORD,//- nv_counter used password
        ESYS_TR_NONE, 
        &qualifyingData, &inScheme, 8,//- nv_counter is 8-bytes
        0, &certifyInfo, &signature);
    if (rc != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " NV_Certify failed." 
            << " Error detail: " << Tss2_RC_Decode(rc);
        return ;
    }
    if (certifyInfo->size > buffer_size) {
        LOG(ERROR) << "Func: " << __FUNCTION__ 
            << " Buffer size is too small, expected size = ."  << certifyInfo->size
            << " Error detail: " << Tss2_RC_Decode(rc);
        return ;
    }
    //- Copy return value to the enclave
    memcpy(attested_data, certifyInfo->attestationData, certifyInfo->size);
    *attest_size = certifyInfo->size;
    memcpy(sig_data, signature->signature.rsassa.sig.buffer, 
            signature->signature.rsassa.sig.size);
    return ;
}

//- If defined, return true. Return false otherwise.
bool is_nv_defined(uint32_t nv_handle) {
    bool is_defined = false;
    TSS2_RC rc = create_nv_counter(nv_handle);
    if (rc != 0) {
        is_defined = true;
    }
    return is_defined;
}


TSS2_RC create_nv_counter(uint32_t nv_handle) {
    TSS2_RC rc = 0;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    TPM2B_NV_PUBLIC *nvPublic = NULL;
    TPM2B_NAME *nvName = NULL;
    TPM2B_MAX_NV_BUFFER *nv_test_data = NULL;
    TPM2B_AUTH auth = {.size = 0, .buffer = {}};
    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex = nv_handle,
            .nameAlg = TPM2_ALG_SHA256,
            .attributes =
                (TPMA_NV_OWNERWRITE | TPMA_NV_WRITE_STCLEAR |
                    TPMA_NV_OWNERREAD | TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT),
            .authPolicy = {.size = 0, .buffer = {}},
            .dataSize = 8,
    }};

    rc = Esys_NV_DefineSpace(tpm_ctx, ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD,
                            // ESYS_TR_NONE,
                            ESYS_TR_NONE, ESYS_TR_NONE, &auth, &publicInfo,
                            &nvHandle);
    if (rc != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Esys_NV_DefineSpace failed."
            << " Detail: " << Tss2_RC_Decode(rc);
        return rc;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " NV_DefineSpace, counter_id = " 
        << int_to_hex(nv_handle);

    rc = Esys_NV_Increment(tpm_ctx, ESYS_TR_RH_OWNER, nvHandle,
                          ESYS_TR_PASSWORD,
                          ESYS_TR_NONE, 
                          ESYS_TR_NONE);
    if (rc != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Esys_NV_Increment failed"
            << " Detail: " << Tss2_RC_Decode(rc);
        return rc;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " Incremented, counter_id = " 
        << int_to_hex(nv_handle);
    return rc;
}

TSS2_RC create_hybrid_nv_counter(uint32_t nv_handle) {
    TSS2_RC rc = 0;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    TPM2B_NV_PUBLIC *nvPublic = NULL;
    TPM2B_NAME *nvName = NULL;
    TPM2B_MAX_NV_BUFFER *nv_test_data = NULL;
    TPM2B_AUTH auth = {.size = 0, .buffer = {}};
    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex = nv_handle,
            .nameAlg = TPM2_ALG_SHA256,
            .attributes =
                (TPMA_NV_OWNERWRITE | TPMA_NV_WRITE_STCLEAR | TPMA_NV_ORDERLY |
                TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE | TPMA_NV_OWNERREAD |
                 TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT),
            .authPolicy = {.size = 0, .buffer = {}},
            .dataSize = 8,
    }};

    rc = Esys_NV_DefineSpace(tpm_ctx, ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD,
                            ESYS_TR_NONE, ESYS_TR_NONE, &auth, &publicInfo,
                            &nvHandle);
    if (rc != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Esys_NV_DefineSpace failed."
            << " Detail: " << Tss2_RC_Decode(rc);
        return rc;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " NV_DefineSpace, counter_id = " 
        << int_to_hex(nv_handle);

    // rc = Esys_NV_Increment(tpm_ctx, ESYS_TR_RH_OWNER, nvHandle,
    rc = Esys_NV_Increment(tpm_ctx, nvHandle, nvHandle,
                          ESYS_TR_PASSWORD,
                          ESYS_TR_NONE, 
                          ESYS_TR_NONE);
    if (rc != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Esys_NV_Increment failed"
            << " Detail: " << Tss2_RC_Decode(rc);
        return rc;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " Incremented, counter_id = " 
        << int_to_hex(nv_handle);
    return rc;
}

int clear_counters(uint32_t nv_first, uint32_t nv_last) {
    uint32_t nv_handle = 0;
    TSS2_RC rc = 0;
    int cnt = 0;
    for (nv_handle = nv_first; nv_handle <= nv_last; nv_handle++) {
        int counter_handle = get_handler_by_counterID(nv_handle, tpm_ctx);
        if (counter_handle == -1) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << "nv_index " 
                << int_to_hex(nv_handle) << " may not exist";
            continue;
        }
        rc = Esys_NV_UndefineSpace(tpm_ctx, ESYS_TR_RH_OWNER, counter_handle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
        if (rc != 0) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << "nv_index " 
                << int_to_hex(nv_handle) << " exists but can't be undefined";
        }
        cnt++;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " Undefined " << cnt
        << " counters totally.";
}

void get_performance(uint32_t nv_handle) {
    TPM2B_MAX_NV_BUFFER *nv_test_data = NULL;
    int counter_handle = get_handler_by_counterID(nv_handle, tpm_ctx);
    LOG(INFO) << "Func: " << __FUNCTION__ << " nv_index = " 
        << int_to_hex(nv_handle) << " START TEST...";
    int rc = 0;
    int i = 0;
    std::chrono::time_point<std::chrono::system_clock> a = std::chrono::system_clock::now();
    timespec sleep_ns = {0, 100000000};
    for (i = 0; i < 10; i++) {
        rc = Esys_NV_Increment(tpm_ctx, ESYS_TR_RH_OWNER, counter_handle,
                          ESYS_TR_PASSWORD,
                          ESYS_TR_NONE, 
                          ESYS_TR_NONE);

        // rc = Esys_NV_Read(tpm_ctx, ESYS_TR_RH_OWNER, counter_handle, 
        //              ESYS_TR_PASSWORD,
        //              ESYS_TR_NONE, 
        //              ESYS_TR_NONE, 8, 0, &nv_test_data);     

        // rc = certify_counter(counter_handle);              
        if (rc != 0) {
            break;
        }
        nanosleep(&sleep_ns, NULL);
    }
    std::chrono::time_point<std::chrono::system_clock> b = std::chrono::system_clock::now();
    
    std::chrono::duration<double, std::milli> elapsed = b - a;
    LOG(INFO) << "The elapsed = " << elapsed.count() << "ms" << " i = " << i;
    return ;
}

void get_performance_sys(uint32_t nv_handle) {
    TSS2_TCTI_CONTEXT *tcti_ctx = tcti_device_init("/dev/tpmrm0");
    TSS2_SYS_CONTEXT *sys_ctx = sys_init_from_tcti_ctx(tcti_ctx);
    TPM2B_MAX_NV_BUFFER *nv_test_data = NULL;
    LOG(INFO) << "Func: " << __FUNCTION__ << " nv_index = " 
        << int_to_hex(nv_handle) << " START TEST...";
    int rc = 0;
    int i = 0;
    std::chrono::time_point<std::chrono::system_clock> a = std::chrono::system_clock::now();
    timespec sleep_ns = {0, 100000000};
    TSS2L_SYS_AUTH_COMMAND cmd_auth = {
        .count = 1,
        .auths = {{
            .sessionHandle = TPM2_RS_PW,       
        }},
    };
    cmd_auth.auths[0].hmac.size = 0;
    for (i = 0; i < 10; i++) {
        rc = Tss2_Sys_NV_Increment(sys_ctx,
                        nv_handle,
                        nv_handle,
                        &cmd_auth,
                        NULL); 

        // rc = Esys_NV_Read(tpm_ctx, ESYS_TR_RH_OWNER, counter_handle, 
        //              ESYS_TR_PASSWORD,
        //              ESYS_TR_NONE, 
        //              ESYS_TR_NONE, 8, 0, &nv_test_data);     

        // rc = certify_counter(counter_handle);              
        if (rc != 0) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << " increament failed..." << Tss2_RC_Decode(rc);
            break;
        }
        nanosleep(&sleep_ns, NULL);
    }
    std::chrono::time_point<std::chrono::system_clock> b = std::chrono::system_clock::now();
    
    std::chrono::duration<double, std::milli> elapsed = b - a;
    LOG(INFO) << "The elapsed = " << elapsed.count() << "ms" << " i = " << i;
    return ;
}

TSS2_RC certify_counter(uint32_t nv_handle) {
    TPM2B_ATTEST *certifyInfo = NULL;
    TPMT_SIGNATURE *signature = NULL;
    TPM2B_DATA qualifyingData = {.size = 3, .buffer = {7, 8, 9}};
    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };
    return Esys_NV_Certify(
        tpm_ctx, 
        ak_handler, 
        ESYS_TR_RH_OWNER,
        nv_handle, 
        ESYS_TR_PASSWORD,
        ESYS_TR_PASSWORD,//- nv_counter used password
        ESYS_TR_NONE, 
        &qualifyingData, &inScheme, 8,//- nv_counter is 8-bytes
        0, &certifyInfo, &signature);
}

void esys_session_test(uint32_t counter_index) {
    TSS2_RC rc;
    uint32_t counter_handle = get_handler_by_counterID(counter_index, tpm_ctx);

    //- Session things
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
                              .keyBits = {.aes = 128},
                              .mode = {.aes = TPM2_ALG_CFB}
    };
    TPMA_SESSION sessionAttributes;
    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };
    memset(&sessionAttributes, 0, sizeof sessionAttributes);
    rc = Esys_StartAuthSession(tpm_ctx, ak_handler, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                              &session);
    if (rc != 0) {
        LOG(ERROR) << "StartAuthSession failed. " << Tss2_RC_Decode(rc);
        return ;
    }
    rc = Esys_NV_Increment(tpm_ctx, counter_handle, counter_handle,
                          session,
                          ESYS_TR_NONE, 
                          ESYS_TR_NONE);
    if (rc != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Esys_NV_Increment failed"
            << " Detail: " << Tss2_RC_Decode(rc);
        return ;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " Incremented, counter_id = " 
        << int_to_hex(counter_index);
}


int create_counters(std::vector<uint32_t> &list) {
    int created_count = 0;
    for (uint32_t index: list) {
        TSS2_RC rc = 0;
        ESYS_TR nvHandle = ESYS_TR_NONE;
        TPM2B_NV_PUBLIC *nvPublic = NULL;
        TPM2B_AUTH auth = {.size = 0, .buffer = {}};
        TPM2B_NV_PUBLIC publicInfo = {
            .size = 0,
            .nvPublic = {
                .nvIndex = index,
                .nameAlg = TPM2_ALG_SHA256,                
                .attributes =
                    (TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE | 
                    TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT),
                .authPolicy = {.size = 0, .buffer = {}},
                .dataSize = 8,
        }};

        rc = Esys_NV_DefineSpace(tpm_ctx, ESYS_TR_RH_OWNER,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE, ESYS_TR_NONE, &auth, &publicInfo,
                                &nvHandle);
        if (rc != 0) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << " Esys_NV_DefineSpace failed."
                << " Detail: " << Tss2_RC_Decode(rc)
                << " counter_index = " << int_to_hex(index);
            continue;
        }

        rc = Esys_NV_Increment(tpm_ctx, nvHandle, nvHandle,
                          ESYS_TR_PASSWORD,
                          ESYS_TR_NONE, 
                          ESYS_TR_NONE);
        if (rc != 0) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << " Esys_NV_Increment failed"
                << " Detail: " << Tss2_RC_Decode(rc)
                << " counter_index = " << int_to_hex(index);
            continue;
        }
        created_count++;
    }
    LOG(INFO) << "created_count = " << created_count;
    return 0;
}

//- The same with create_counters except that it creates hybrid ones.
int create_counters_hybrid(std::vector<uint32_t> &list) {
    int created_count = 0;
    for (uint32_t index: list) {
        TSS2_RC rc = 0;
        ESYS_TR nvHandle = ESYS_TR_NONE;
        TPM2B_NV_PUBLIC *nvPublic = NULL;
        TPM2B_AUTH auth = {.size = 0, .buffer = {}};
        TPM2B_NV_PUBLIC publicInfo = {
            .size = 0,
            .nvPublic = {
                .nvIndex = index,
                .nameAlg = TPM2_ALG_SHA256,                
                .attributes =
                    (TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE | TPMA_NV_ORDERLY |
                    TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT),
                .authPolicy = {.size = 0, .buffer = {}},
                .dataSize = 8,
        }};

        rc = Esys_NV_DefineSpace(tpm_ctx, ESYS_TR_RH_OWNER,
                                ESYS_TR_PASSWORD,
                                ESYS_TR_NONE, ESYS_TR_NONE, &auth, &publicInfo,
                                &nvHandle);
        if (rc != 0) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << " Esys_NV_DefineSpace failed."
                << " Detail: " << Tss2_RC_Decode(rc)
                << " counter_index = " << int_to_hex(index);
            continue;
        }

        rc = Esys_NV_Increment(tpm_ctx, nvHandle, nvHandle,
                          ESYS_TR_PASSWORD,
                          ESYS_TR_NONE, 
                          ESYS_TR_NONE);
        if (rc != 0) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << " Esys_NV_Increment failed"
                << " Detail: " << Tss2_RC_Decode(rc)
                << " counter_index = " << int_to_hex(index);
            continue;
        }
        created_count++;
    }
    LOG(INFO) << "created_count = " << created_count;
    return 0;
}

int clear_counters(std::vector<uint32_t> &list) {
    int remove_cnt = 0;
    int rc;
    for (uint32_t index: list) {
        int counter_handle = get_handler_by_counterID(index, tpm_ctx);
        if (counter_handle == -1) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << "nv_index " 
                << int_to_hex(index) << " may not exist";
            continue;
        }
        rc = Esys_NV_UndefineSpace(tpm_ctx, ESYS_TR_RH_OWNER, counter_handle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
        if (rc != 0) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << "nv_index " 
                << int_to_hex(index) << " exists but can't be undefined";
            continue;
        }
        remove_cnt++;
    }
    LOG(INFO) << "remove_cnt = " << remove_cnt;
    return 0;
}    