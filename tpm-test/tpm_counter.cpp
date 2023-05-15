#include "tpm_counter.h"
#include "easylogging++.h"


extern int node_num;

//- The public key of the attestation key
std::string ak_pub = "-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApLnajj+ZeZeomv+uHtFi\n"
"ulWD3XiUvUqSC91gJUlb2Qjwaviq0GrlbQf5DWJsiioL+3ps1/InH4RRkQlDAPqu\n"
"kwLprqvkaf7M4rPRtdYpgglkJd4gvlaF7id9+ZF4CNTAvbI2fg/taFVT7JCrDUkP\n"
"84Z/QhC7sDYlWJ5dajc5fiXjDrmKIgdol1PV7Eg6NDyCwkqRejueq/eYAIbharDt\n"
"x6s2sFH9oqxmXRHpIW288Fwq68o4k5KBV+ey0w2Oy7dpeeri+usT0LVnzIrVR4u/\n"
"K1HH6KGkpIOnmwPtQyM381/XrqGRsEaAxgxMyUGqUFxJhY0g1ojjHxhfvnIPMyBv\n"
"5wIDAQAB\n"
"-----END PUBLIC KEY-----";

void play_with_TPM() {
    ESYS_CONTEXT *tpm_ctx;
    int rc = Esys_Initialize(&tpm_ctx, NULL, NULL);
    if (rc != 0) {
        LOG(ERROR) << "Esys_Initialize failed";
    }
    //- TEST 1. create counter and save index in the file   
    CounterID counter_id = 0x01000000;
    // CounterID counter_id = 0x01000001;
    // CounterID counter_id = 0x01000002;
    // std::fstream counter_handle("tpm_couter_nvhandle.dat", std::fstream::out);
    // if (create_counter(counter_id, tpm_ctx) != 0) {
    //     LOG(ERROR) << "Create counter failed.";        
    // }
    // counter_handle << counter_id;
    // counter_handle.close();

    //- TEST 2. read counter index from file and then get its value
    // CounterID counter_id_in = 0;
    // std::fstream counter_handle_in("tpm_couter_nvhandle.dat", std::fstream::in);
    // counter_handle_in >> counter_id_in;
    // LOG(INFO) << "counter_id_in = " << counter_id_in;
    // counter_handle_in.close();
    // if (destroy_counter(counter_id_in, tpm_ctx) != 0) {
    //     LOG(ERROR) << "Destroyed counter failed.";
    // }

    //- TEST 3. Use nv_certify to read counter value
    counter_certify(counter_id, tpm_ctx);
}

int counter_certify(CounterID counter_id, ESYS_CONTEXT *esys_context) {
    TSS2_RC r;
    TPM2B_ATTEST *certifyInfo = NULL;
    TPMT_SIGNATURE *signature = NULL;
    //- #1. Get attestation key (AK) persistent in ak_nv_index
    uint32_t ak_nv_index = 0x81010002;
    ESYS_TR ak_handler;
    r = Esys_TR_FromTPMPublic(esys_context, ak_nv_index, ESYS_TR_NONE, ESYS_TR_NONE,
                            ESYS_TR_NONE, &ak_handler);
    if (r != 0) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " Get ak_nv_index failed.";
        return -1;
    }

    //- #2. Call nv_certify (AK as signing key)
    ESYS_TR counter_handler = get_handler_by_counterID(counter_id, esys_context);
    
    //- TEST nvpublic
    // TPM2B_NV_PUBLIC *nvPublic = NULL;
    // TPM2B_NAME *nvName = NULL;
    // r = Esys_NV_ReadPublic(esys_context, counter_handler, ESYS_TR_NONE, ESYS_TR_NONE,
    //                        ESYS_TR_NONE, &nvPublic, &nvName);
    // LOG(INFO) << "nvPublic.size = " << nvPublic->size << " nvName = " << nvName
    //     << " \n\tnvPublic.nvPublic fields: \n\t"
    //     << "nvIndex = " << nvPublic->nvPublic.nvIndex << "\n\t"
    //     << "dataSize = " << nvPublic->nvPublic.dataSize;

    TPM2B_DATA qualifyingData = {.size = 3, .buffer = {7, 8, 9}};
    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };
    r = Esys_NV_Certify(
        esys_context, 
        ak_handler, 
        ESYS_TR_RH_OWNER,
        counter_handler, 
        ESYS_TR_PASSWORD,
        ESYS_TR_PASSWORD,//- nv_counter used password
        ESYS_TR_NONE, 
        &qualifyingData, &inScheme, 8,//- nv_counter is 8-bytes
        0, &certifyInfo, &signature);
    if (r != 0) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " NV_Certify failed." 
            << " Error detail: " << Tss2_RC_Decode(r);
        return -1;
    }
    LOG(INFO) << "Attested data size = " << certifyInfo->size;
    //- #3. Verify the return value of nv_certify
    TPMS_ATTEST cert_info;
    Tss2_MU_TPMS_ATTEST_Unmarshal(certifyInfo->attestationData, certifyInfo->size,
                                 0, &cert_info);
    LOG(INFO) << "Clock = " << cert_info.clockInfo.clock;
    TPM2B_DATA qualify_data;
    //- #3.1 Verify the signature
    //- Value 20 means TPM2_ALG_RSASSA
    LOG(INFO) << "Sig_Algo = " << signature->sigAlg;
    //- Value 11 means TPM2_ALG_SHA256
    LOG(INFO) << "Sig_hash = " << signature->signature.rsassa.hash;
    //- The SHA-256 signature is inside signature->signature.rsassa.sig
    LOG(INFO) << "Sig_lenth_bytes = " << signature->signature.rsassa.sig.size;
    //- Signature itself is inside signature->signature.rsassa.sig.buffer, 
    //- totally 2048 bits (256 bytes)
    bool pass = verify_signature(
        createPublicRSA(ak_pub), 
        certifyInfo->attestationData, 
        certifyInfo->size,
        signature->signature.rsassa.sig.buffer,
        signature->signature.rsassa.sig.size);
    LOG(INFO) << "pass = " << pass;

    //- #3.2 Signature is verifyied, then qualify_data
    // LOG(INFO) << "The size of qualified data = " << cert_info.extraData.size;
    // for (int i = 0; i < cert_info.extraData.size; i++) {
    //     printf("#1 Byte-%d: %02x\n", i, cert_info.extraData.buffer[i]);
    // }

    //- #3.3 Read trusted counter value
    TPM2B_NAME *expected_name = NULL;
    r = Esys_TR_GetName(esys_context, counter_handler, &expected_name);

    // LOG(INFO) << "cert_info.attested.nv.indexName.size = "
    //     << cert_info.attested.nv.indexName.size;
    // LOG(INFO) << "expected_name.size = " << expected_name->size;
    // for (int i = 0; i < cert_info.attested.nv.indexName.size; i++) {
    //     printf("#2 Byte-%d: %02x, %02x\n", i, 
    //         cert_info.attested.nv.indexName.name[i],
    //         expected_name->name[i]);
    //     if (cert_info.attested.nv.indexName.name[i] != expected_name->name[i]) {
    //         LOG(ERROR) << "Dismatch...";
    //         break;
    //     }         
    // }

    LOG(INFO) << "Expected nv_index = " << counter_id;
    uint64_t counter_value = 0;
    r = Tss2_MU_UINT64_Unmarshal(cert_info.attested.nv.nvContents.buffer, 8, 
                            NULL, &counter_value);
    LOG(INFO) << "counter_value = " << counter_value;
    return 0;
}

int create_counter(CounterID counter_id, ESYS_CONTEXT *esys_context) {
    uint64_t value = 0;
    TSS2_RC r;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    TPM2B_NV_PUBLIC *nvPublic = NULL;
    TPM2B_NAME *nvName = NULL;
    TPM2B_MAX_NV_BUFFER *nv_test_data = NULL;
    TPM2B_AUTH auth = {.size = 0, .buffer = {}};
    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex = (uint32_t)counter_id,
            .nameAlg = TPM2_ALG_SHA256,
            .attributes =
                (TPMA_NV_OWNERWRITE | TPMA_NV_WRITE_STCLEAR | 
                    TPMA_NV_OWNERREAD | TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT),
            .authPolicy = {.size = 0, .buffer = {}},
            .dataSize = 8,
    }};

    r = Esys_NV_DefineSpace(esys_context, ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD,
                            // ESYS_TR_NONE,
                            ESYS_TR_NONE, ESYS_TR_NONE, &auth, &publicInfo,
                            &nvHandle);
    goto_if_error(r, "Error esys define nv space", error);
    LOG(INFO) << " NV_DefineSpace, counter_id = " << counter_id;
    
    r = Esys_NV_ReadPublic(esys_context, nvHandle, ESYS_TR_NONE, ESYS_TR_NONE,
                           ESYS_TR_NONE, &nvPublic, &nvName);
    goto_if_error(r, "Error: nv read public", error);
    LOG(INFO) << "nvPublic.size = " << nvPublic->size << " nvName = " << nvName
        << " \n\tnvPublic.nvPublic fields: \n\t"
        << "nvIndex = " << nvPublic->nvPublic.nvIndex << "\n\t"
        << "dataSize = " << nvPublic->nvPublic.dataSize;

    r = Esys_NV_Increment(esys_context, ESYS_TR_RH_OWNER, nvHandle,
                          ESYS_TR_PASSWORD,
                          ESYS_TR_NONE, 
                          ESYS_TR_NONE);
    goto_if_error(r, "Error esys nv write", error);

    //- Read the conter for the second time
    r = Esys_NV_Read(esys_context, ESYS_TR_RH_OWNER, nvHandle, 
                     ESYS_TR_PASSWORD,
                     ESYS_TR_NONE, 
                     ESYS_TR_NONE, 8, 0, &nv_test_data);
    goto_if_error(r, "Error esys nv read", error);
    
    r = Tss2_MU_UINT64_Unmarshal(nv_test_data->buffer, 8, NULL, &value);
    LOG(INFO) << "nv_read_val = " << value;

    Esys_Free(nvPublic);
    Esys_Free(nvName);
    Esys_Free(nv_test_data);
    return EXIT_SUCCESS;

error:
    Esys_Free(nvPublic);
    Esys_Free(nvName);
    Esys_Free(nv_test_data);
    return EXIT_FAILURE;
}

int destroy_counter(CounterID counter_id, ESYS_CONTEXT *esys_context) {
    TSS2_RC r;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    TPM2_HANDLE handle_nv = (uint32_t)counter_id;
    LOG(INFO) << "Func: " << __FUNCTION__ << " TPM2_HANDLE = " << handle_nv;
    TPM2B_NV_PUBLIC *nvPublic = NULL;
    TPM2B_NAME *nvName = NULL;
    TPM2B_MAX_NV_BUFFER *nv_test_data = NULL;

    r = Esys_TR_FromTPMPublic(esys_context, handle_nv, ESYS_TR_NONE, ESYS_TR_NONE,
                            ESYS_TR_NONE, &nvHandle);
    goto_if_error(r, "Error Esys_TR_FromTPMPublic", error);
    LOG(INFO) << "Func: " << __FUNCTION__ << " Retrieve handle = " << nvHandle;

    r = Esys_NV_Increment(esys_context, ESYS_TR_RH_OWNER, nvHandle,
                          ESYS_TR_PASSWORD,
                          ESYS_TR_NONE, ESYS_TR_NONE);                          
    goto_if_error(r, "Error esys nv write", error);

    r = Esys_NV_Read(esys_context, ESYS_TR_RH_OWNER, nvHandle,
                     ESYS_TR_PASSWORD,
                     ESYS_TR_NONE, ESYS_TR_NONE, 8, 0, &nv_test_data);
    goto_if_error(r, "Error esys nv read", error);
    uint64_t value;
    r = Tss2_MU_UINT64_Unmarshal (nv_test_data->buffer, 8, NULL, &value);
    LOG(INFO) << "nv_read_val = " << value;

    r = Esys_NV_UndefineSpace(esys_context, ESYS_TR_RH_OWNER, nvHandle,
                              ESYS_TR_PASSWORD,
                              ESYS_TR_NONE, ESYS_TR_NONE);
    goto_if_error(r, "Error: NV_UndefineSpace", error);

    Esys_Free(nvPublic);
    Esys_Free(nvName); 
    Esys_Free(nv_test_data);
    return EXIT_SUCCESS;

error:

    Esys_Free(nvPublic);
    Esys_Free(nvName);
    Esys_Free(nv_test_data);
    return EXIT_FAILURE;
}

int get_handler_by_counterID(CounterID counter_id, ESYS_CONTEXT *esys_context) {
    TSS2_RC r;
    ESYS_TR nvHandle = ESYS_TR_NONE;
    TPM2_HANDLE handle_nv = (uint32_t)counter_id;
    LOG(INFO) << "Func: " << __FUNCTION__ << " TPM2_HANDLE = " << handle_nv;

    r = Esys_TR_FromTPMPublic(esys_context, handle_nv, ESYS_TR_NONE, ESYS_TR_NONE,
                            ESYS_TR_NONE, &nvHandle);
    goto_if_error(r, "Error Esys_TR_FromTPMPublic", error);
    LOG(INFO) << "Func: " << __FUNCTION__ << " Retrieve handle = " << nvHandle;

    return nvHandle;

error:
    return -1;
}

RSA* createPublicRSA(std::string key) {
  RSA *rsa = NULL;
  BIO *keybio;
  const char* c_string = key.c_str();
  keybio = BIO_new_mem_buf((void*)c_string, -1);
  if (keybio==NULL) {
      return 0;
  }
  rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
  return rsa;
}

bool verify_signature(RSA *publicKey, unsigned char *data, int data_size, 
                        unsigned char *sig, int sig_size) {
    bool pass = false;
    EVP_PKEY* pubKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, publicKey);
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey)<=0) {
        return pass;
    }
    if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, data, data_size) <= 0) {
        return pass;
    }
    int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, sig, sig_size);
    if (AuthStatus == 1) {
        pass = true;
    }
    EVP_MD_CTX_reset(m_RSAVerifyCtx);
    return pass;
}