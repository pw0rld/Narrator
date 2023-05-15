/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2019, Intel Corporation
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <chrono>
#include <openssl/engine.h>

#include <tss2_sys.h>
#include <tss2_rc.h>
extern "C" {
    #include "sys-context-util.h"
    #include "sys-util.h"
    #include "sys-session-util.h"
    #include "sys-hmac-auth.int2.h"
    #define LOGMODULE test
    #include "tpm_test_util/log.h"
}
#include "tpm_counter.h"

#define TPM20_INDEX_PASSWORD_TEST       0x1500020
// TPMI_DH_OBJECT ak_nv_handle = 0x81010002;
TPMI_DH_OBJECT ek_nv_handle = 0x81010010;
//- The public key of the endorsement key
std::string tpmKey = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7UH5dWQL5qwJefRAsJ6O\n"
"Q13ECJLedB2bgSScKd8vWHKDXqVg/k2yesYprnSDr/5IvFf2bwK6icJwqtqQogBD\n"
"a56LZ4oxEHdokqOA10oZfpM5HGQNzwZRr+MkUJ28LI6vy/Uhy56ltd2dAWq296r9\n"
"rAZHN2f4gRXxtCcGxSdpRN7MgrmpULnUTc3Lfr9TiF8r/ApHxLEvd2GziG3+gIjJ\n"
"oSoTZ6ZSghUKh3KjvrBVnFh+3ey2udvNv9jEXVdwRzlYz4DACJTWz/7S0tALkuJu\n"
"u/dkMVMiuP1Iva1YYWIHVWgwoghzO0bhQ46H1osDum5/DPybrkkUxP4Ds4KS8NgV\n"
"eQIDAQAB\n"
"-----END PUBLIC KEY-----";

/** Compute random TPM2B data.
 *
 * The random data will be generated and written to a passed TPM2B structure.
 * @param[out] nonce The TPM2B structure for the random data (caller-allocated).
 * @param[in] num_bytes The number of bytes to be generated.
 * @retval TSS2_RC_SUCCESS on success.
 *
 * NOTE: the TPM should not be used to obtain the random data
 */
TSS2_RC
iesys_cryptossl_random2b(TPM2B_NONCE * nonce, size_t num_bytes)
{
    const RAND_METHOD *rand_save = RAND_get_rand_method();

    if (num_bytes == 0) {
        nonce->size = sizeof(TPMU_HA);
    } else {
        nonce->size = num_bytes;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    RAND_set_rand_method(RAND_OpenSSL());
#else
    RAND_set_rand_method(RAND_SSLeay());
#endif
    if (1 != RAND_bytes(&nonce->buffer[0], nonce->size)) {
        RAND_set_rand_method(rand_save);
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE,
                     "Failure in random number generator.");
    }
    RAND_set_rand_method(rand_save);
    return TSS2_RC_SUCCESS;
}

int generate_salt(TSS2_SYS_CONTEXT *sys_ctx, TPM2B_MAX_BUFFER* Salt, TPM2B_ENCRYPTED_SECRET* encryptedSalt) {
    size_t out_size;

    //- According to iesys_compute_encrypted_salt in esys_iutil.c
    if (iesys_cryptossl_random2b((TPM2B_NONCE*) Salt, 32) != 0) {
       LOG_ERROR("iesys_cryptossl_random2b failed");
       return -1;
    }
    LOG_INFO("Salt.size = %d", Salt->size);

    RSA* pub_key = createPublicRSA(tpmKey);
    if (pub_key != NULL) {
        LOG_INFO("key generated.");
    }

    TSS2_RC rc = TSS2_RC_SUCCESS;
    //- The name algorithm of EK is SHA-256
    const EVP_MD * hashAlg = EVP_sha256();
    EVP_PKEY *evp_rsa_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_rsa_key, pub_key);

    EVP_PKEY_CTX *ctx = NULL;

    //- When encrypting salts, the encryption scheme of a key is ignored and 
    //- TPM2_ALG_OAEP is always used, and thus the padding pattern is as follows.
    int padding = RSA_PKCS1_OAEP_PADDING;

    char *label_copy = OPENSSL_strdup("SECRET");
    if (!label_copy) {
        goto_error(rc, TSS2_ESYS_RC_MEMORY,
                   "Could not duplicate OAEP label", cleanup);
    }

    if (!(ctx = EVP_PKEY_CTX_new(evp_rsa_key, NULL))) {
        goto_error(rc, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not create evp context.", cleanup);
    }

    if (1 != EVP_PKEY_encrypt_init(ctx)) {
        goto_error(rc, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not init encrypt context.", cleanup);
    }

    if (1 != EVP_PKEY_CTX_set_rsa_padding(ctx, padding)) {
        goto_error(rc, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not set RSA passing.", cleanup);
    }

    if (1 != EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label_copy, strlen(label_copy)+1)) {
        OPENSSL_free(label_copy);
        goto_error(rc, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not set RSA label.", cleanup);
    }

    if (1 != EVP_PKEY_CTX_set_rsa_oaep_md(ctx, hashAlg)) {
        goto_error(rc, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not set hash algorithm.", cleanup);
    }

    /* Determine out size */
    if (1 != EVP_PKEY_encrypt(ctx, NULL, &out_size, Salt->buffer, Salt->size)) {
        goto_error(rc, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not determine ciper size.", cleanup);
    }
    LOG_INFO("Encrypted data length = %ld", out_size);
    encryptedSalt->size = out_size;

    /* Encrypt data */
    if (1 != EVP_PKEY_encrypt(ctx, 
                            encryptedSalt->secret, 
                            &out_size, 
                            Salt->buffer, 
                            Salt->size)) {
        goto_error(rc, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "Could not encrypt data.", cleanup);
    }
    LOG_INFO("Encryption finished");
    
    return 0;


cleanup:
    return -1;
    // const TSS2L_SYS_AUTH_COMMAND auth_cmd_null_pwd = {
    //     .count = 1,
    //     .auths = {
    //         {
    //             .sessionHandle = TPM2_RS_PW,
    //         },
    //     },
    // };
    // TPM2B_PUBLIC key_info;
    // TPM2B_NAME name = TPM2B_NAME_INIT;
    // TPM2B_NAME qual_name = TPM2B_NAME_INIT;
    // TSS2L_SYS_AUTH_RESPONSE resp;
    // int rc = Tss2_Sys_ReadPublic(sys_ctx, ek_nv_handle, &auth_cmd_null_pwd, &key_info, &name, 
    //     &qual_name, &resp);
    // if (rc != 0) {
    //     LOG_ERROR("readpublic failed, detail:%s", Tss2_RC_Decode(rc));
    // }
    // LOG_INFO("padding = %d", (int)key_info.publicArea.parameters.rsaDetail.scheme.scheme);
    // LOG_INFO("size = %d", (int)key_info.size);
    // LOG_INFO("nameAlg = %d", (int)key_info.publicArea.nameAlg);
    // LOG_INFO("exp = %d", key_info.publicArea.parameters.rsaDetail.exponent);
}

void update_command_nonce(int bytes, TPM2B_NONCE* nonce) {
    LOG_INFO("update_command_nonce");
    int ret = RAND_bytes(nonce->buffer, bytes);
    if (ret == 1) {
        //- openssl return success
        nonce->size = bytes;
        return;
    } else if (ret == -1){
        LOG_ERROR(" Not supported by the current RAND method.");
    } else {
        unsigned long err = ERR_get_error();
        LOG_ERROR(" error num = %ld", err);
    }
    return ;
}

TSS2_RC
nv_rw_with_session2 (
    TSS2_SYS_CONTEXT *sys_ctx,
    const TPM2B_DIGEST *authPolicy,
    TPMA_NV nvAttributes,
    TPM2_SE session_type)
{
    TSS2_RC rc;
    //- Use empty auth.
    TPM2B_AUTH  nvAuth = {0, };
    SESSION *nvSession = NULL;
    TPM2B_NAME nvName;
    TPM2B_NONCE nonceCaller = { 0, };
    TPM2B_MAX_NV_BUFFER nvReadData = { .size = TPM2B_SIZE (nvReadData), };
    TPM2B_MAX_BUFFER plainSalt;
    TPM2B_ENCRYPTED_SECRET encryptedSalt;
    rc = generate_salt(sys_ctx, &plainSalt, &encryptedSalt);
    if (rc != 0) {
        return -1;
    }
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL,
    };
    TSS2_TCTI_CONTEXT *tcti_ctx;
    TSS2L_SYS_AUTH_RESPONSE nvRspAuths;
    TSS2L_SYS_AUTH_COMMAND nvCmdAuths = {
        .count = 1,
        .auths= {
            {
                .sessionHandle = TPM2_RS_PW,
                .nonce = {
                    .size = 1,
                    .buffer = { 0xa5, },
                },                
                .sessionAttributes = TPMA_SESSION_CONTINUESESSION,
            }
        }
    };
    const TSS2L_SYS_AUTH_COMMAND auth_cmd_null_pwd = {
        .count = 1,
        .auths = {
            {
                .sessionHandle = TPM2_RS_PW,
            },
        },
    };


    rc = Tss2_Sys_GetTctiContext (sys_ctx, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS || tcti_ctx == NULL) {
        LOG_ERROR ("Failed to get TCTI from Sys context, got RC: 0x%x", rc);
        return TSS2_SYS_RC_GENERAL_FAILURE;
    }

    rc = DefineNvIndex (sys_ctx,
                        TPM2_RH_OWNER,
                        &nvAuth,
                        authPolicy,
                        TPM20_INDEX_PASSWORD_TEST,
                        TPM2_ALG_SHA256,
                        nvAttributes,
                        8);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("DefineNvIndex failed with RC: 0x%x detail:%s", rc, Tss2_RC_Decode(rc));
        return rc;
    }

    /*
     * Add index and associated authorization value to
     * entity table.  This helps when we need
     * to calculate HMACs.
     */
    rc = AddEntity(TPM20_INDEX_PASSWORD_TEST, &nvAuth);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("AddEntity failed with RC: 0x%x", rc);
        return rc;
    }

    /* Get the name of the NV index. */
    rc = tpm_handle_to_name (tcti_ctx,
                             TPM20_INDEX_PASSWORD_TEST,
                             &nvName);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("tpm_handle_to_name failed with RC: 0x%x", rc);
        return rc;
    }

    /*
     * Start HMAC or real (non-trial) policy authorization session:
     * it's an unbound and unsalted session, no symmetric
     * encryption algorithm, and SHA256 is the session's
     * hash algorithm.
     */
    std::chrono::time_point<std::chrono::system_clock> time_start_session = 
        std::chrono::system_clock::now();
    rc = create_auth_session (&nvSession,
                              ek_nv_handle,
                              &plainSalt,
                              TPM2_RH_NULL,
                              0,
                              &nonceCaller,
                              &encryptedSalt,
                              session_type,
                              &symmetric,
                              TPM2_ALG_SHA256,
                              tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("create_auth_session failed with RC: 0x%x", rc);
        return rc;
    }    

    /* set handle in command auth */
    nvCmdAuths.auths[0].sessionHandle = nvSession->sessionHandle;

    /*
     * Get the name of the session and save it in
     * the nvSession structure.
     */
    rc = tpm_handle_to_name (tcti_ctx,
                             nvSession->sessionHandle,
                             &nvSession->name);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("tpm_handle_to_name failed with RC: 0x%x", rc);
        return rc;
    }
    std::chrono::time_point<std::chrono::system_clock> time_created_session = 
        std::chrono::system_clock::now();
    int inc_count;
    int total_inc = 1;
    for (inc_count = 0; inc_count < total_inc; inc_count++) {
        /* First call prepare in order to create cpBuffer. */
        rc = Tss2_Sys_NV_Increment_Prepare(sys_ctx,
                                        TPM20_INDEX_PASSWORD_TEST,
                                        TPM20_INDEX_PASSWORD_TEST);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Increment_Prepare failed with RC: 0x%x", rc);
            return rc;
        }
        // LOG_INFO("Increment_Prepare succeed");

        /* Roll nonces for command */
        update_command_nonce(32, &(nvCmdAuths.auths[0].nonce) );
        roll_nonces (nvSession, &nvCmdAuths.auths[0].nonce);

        /*
        * Complete command authorization area, by computing
        * HMAC and setting it in nvCmdAuths.
        */
        rc = compute_command_hmac(sys_ctx,
                                TPM20_INDEX_PASSWORD_TEST,
                                TPM20_INDEX_PASSWORD_TEST,
                                TPM2_RH_NULL,
                                &nvCmdAuths);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("compute_command_hmac failed with RC: 0x%x detail:%s", rc, Tss2_RC_Decode(rc));
            return rc;
        }
        // LOG_INFO("compute_command_hmac succeed");

        /*
        * Finally!!  Write the data to the NV index.
        * If the command is successful, the command
        * HMAC was correct.
        */
        rc = TSS2_RETRY_EXP (Tss2_Sys_NV_Increment(sys_ctx,
                                TPM20_INDEX_PASSWORD_TEST,
                                TPM20_INDEX_PASSWORD_TEST,
                                &nvCmdAuths,
                                &nvRspAuths));                            
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Increment failed with RC: 0x%x detail:%s", rc, Tss2_RC_Decode(rc));
            return rc;
        }
        LOG_INFO("cmd's hamc size = %d", nvCmdAuths.auths[0].hmac.size);
        LOG_INFO("res's hamc size = %d", nvRspAuths.auths[0].hmac.size);
        // LOG_INFO("Increment succeed");


        /* Roll nonces for response */
        roll_nonces (nvSession, &nvRspAuths.auths[0].nonce);

        /*
        * If the command was successful, check the
        * response HMAC to make sure that the
        * response was received correctly.
        */
        rc = check_response_hmac (sys_ctx,
                                &nvCmdAuths,
                                TPM20_INDEX_PASSWORD_TEST,
                                TPM20_INDEX_PASSWORD_TEST,
                                TPM2_RH_NULL,
                                &nvRspAuths);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("check_response_hmac failed with RC: 0x%x", rc);
            return rc;
        }
        LOG_INFO("check_response_hmac PASSED");        
    }
    std::chrono::time_point<std::chrono::system_clock> time_inc
        = std::chrono::system_clock::now();

    int read_count;
    int total_read = 1;
    for (read_count = 0; read_count < total_read; read_count++) {
        /* First call prepare in order to create cpBuffer. */
        rc = Tss2_Sys_NV_Read_Prepare (sys_ctx,
                                    TPM20_INDEX_PASSWORD_TEST,
                                    TPM20_INDEX_PASSWORD_TEST,
                                    8,
                                    0);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Tss2_Sys_NV_Read_Prepare failed with RC: 0x%x", rc);
            return rc;
        }

        update_command_nonce(32, &(nvCmdAuths.auths[0].nonce) );
        roll_nonces (nvSession, &nvCmdAuths.auths[0].nonce);

        /* End the session after next command. */
        if (read_count == (total_read - 1))
            nvCmdAuths.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;

        /*
        * Complete command authorization area, by computing
        * HMAC and setting it in nvCmdAuths.
        */
        rc = compute_command_hmac (sys_ctx,
                                TPM20_INDEX_PASSWORD_TEST,
                                TPM20_INDEX_PASSWORD_TEST,
                                TPM2_RH_NULL,
                                &nvCmdAuths);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("compute_command_hmac failed with RC: 0x%x", rc);
            return rc;
        }

        /*
        * And now read the data back.
        * If the command is successful, the command
        * HMAC was correct.
        */
        rc = Tss2_Sys_NV_Read (sys_ctx,
                            TPM20_INDEX_PASSWORD_TEST,
                            TPM20_INDEX_PASSWORD_TEST,
                            &nvCmdAuths,
                            8,
                            0,
                            &nvReadData,
                            &nvRspAuths);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("Tss2_Sys_NV_Read failed with RC: 0x%x", rc);
            return rc;
        }

        /* Roll nonces for response */
        roll_nonces (nvSession, &nvRspAuths.auths[0].nonce);

        /*
        * If the command was successful, check the
        * response HMAC to make sure that the
        * response was received correctly.
        */
        rc = check_response_hmac (sys_ctx,
                                &nvCmdAuths,
                                TPM20_INDEX_PASSWORD_TEST,
                                TPM20_INDEX_PASSWORD_TEST,
                                TPM2_RH_NULL,
                                &nvRspAuths);
        if (rc != TSS2_RC_SUCCESS) {
            LOG_ERROR ("check_response_hmac failed with RC: 0x%x", rc);
            return rc;
        }
        LOG_INFO("NV_READ response check passed");
    }
    std::chrono::time_point<std::chrono::system_clock> time_read
    = std::chrono::system_clock::now();

    std::chrono::duration<double, std::milli> elapsed_create_session
        = time_created_session - time_start_session;
    std::chrono::duration<double, std::milli> elapsed_inc
        = time_inc - time_created_session;
    std::chrono::duration<double, std::milli> elapsed_read
        = time_read - time_inc;
    LOG_INFO("elapsed_create_session = %lf ms", elapsed_create_session.count());
    LOG_INFO("inc_count = %d, elapsed_inc = %lf ms", inc_count, elapsed_inc.count());
    LOG_INFO("read_count = %d, elapsed_read = %lf ms", read_count, elapsed_read.count());

    /* Undefine the NV index. */
    rc = Tss2_Sys_NV_UndefineSpace (sys_ctx,
                                    TPM2_RH_OWNER,
                                    TPM20_INDEX_PASSWORD_TEST,
                                    &auth_cmd_null_pwd,
                                    0);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Tss2_Sys_NV_UndefineSpace failed with RC: 0x%x", rc);
        return rc;
    }

    /* Delete the NV index's entry in the entity table. */
    DeleteEntity (TPM20_INDEX_PASSWORD_TEST);

    /* Remove the real session from sessions table. */
    end_auth_session (nvSession);
    return rc;
}

TSS2_RC nv_rw_with_session (
    TSS2_SYS_CONTEXT *sys_ctx,
    const TPM2B_DIGEST *authPolicy,
    TPMA_NV nvAttributes,
    TPM2_SE session_type)
{
    TSS2_RC rc;
    //- Use empty auth.
    TPM2B_AUTH  nvAuth = {0, };
    SESSION *nvSession = NULL;
    TPM2B_NAME nvName;
    TPM2B_NONCE nonceCaller = { 32, };
    for (int i = 0; i < nonceCaller.size; i++) {
        nonceCaller.buffer[i] = i;
    }
    TPM2B_MAX_NV_BUFFER nvReadData = { .size = TPM2B_SIZE (nvReadData), };
    TPM2B_MAX_BUFFER plainSalt;
    TPM2B_ENCRYPTED_SECRET encryptedSalt;
    rc = generate_salt(sys_ctx, &plainSalt, &encryptedSalt);
    if (rc != 0) {
        return -1;
    }
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL,
    };

    TPM2_HANDLE session_handle = 0;
    TPM2B_NONCE nonce_tpm;
    nonce_tpm.size = nonceCaller.size;
    std::chrono::time_point<std::chrono::system_clock> time_start_session = 
        std::chrono::system_clock::now();
    rc = Tss2_Sys_StartAuthSession(sys_ctx,
                                    ek_nv_handle,
                                    TPM2_RH_NULL,
                                    0,
                                    &nonceCaller,
                                    &encryptedSalt,
                                    TPM2_SE_HMAC,
                                    &symmetric,
                                    TPM2_ALG_SHA256,
                                    &session_handle,
                                    &nonce_tpm,
                                    0);        
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("create_auth_session failed with RC: 0x%x", rc);
        return rc;
    }
    LOG_INFO("Success! session_handle = %d", session_handle);
   
    return rc;
}

int undefine_test_nv2(TSS2_SYS_CONTEXT *sys_ctx) {
    const TSS2L_SYS_AUTH_COMMAND auth_cmd_null_pwd = {
        .count = 1,
        .auths = {
            {
                .sessionHandle = TPM2_RS_PW,
            },
        },
    };
    int rc = Tss2_Sys_NV_UndefineSpace (sys_ctx,
                                    TPM2_RH_OWNER,
                                    TPM20_INDEX_PASSWORD_TEST,
                                    &auth_cmd_null_pwd,
                                    0);
    if (rc != TSS2_RC_SUCCESS) {
        LOG_ERROR ("Tss2_Sys_NV_UndefineSpace failed with RC: 0x%x detail:%s", rc, Tss2_RC_Decode(rc));
        return rc;
    }
    return 0;
}

int test_invoke2()
{
    TSS2_RC rc;    
    TSS2_TCTI_CONTEXT *tcti_ctx = tcti_device_init("/dev/tpmrm0");
    TSS2_SYS_CONTEXT *sys_ctx = sys_init_from_tcti_ctx(tcti_ctx);
    LOG_INFO("sys context init...");
    
    TPM2B_DIGEST authPolicy = { 0, };
    TPMA_NV nvAttributes;

    LOG_INFO ("HMAC session test");
    // nvAttributes = TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE | TPMA_NV_PLATFORMCREATE;
    nvAttributes = (TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_AUTHREAD | 
            TPMA_NV_AUTHWRITE| TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT);
    // rc = nv_rw_with_session2 (sys_ctx, &authPolicy, nvAttributes, TPM2_SE_HMAC);
    rc = nv_rw_with_session (sys_ctx, &authPolicy, nvAttributes, TPM2_SE_HMAC);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    sys_teardown_full(sys_ctx);
    return TSS2_RC_SUCCESS;
}
