#include <tss2_common.h>
#include <tss2_esys.h>
#include <tss2_mu.h>
#include <tss2_rc.h>
#include <tss2_tpm2_types.h>
#include <string>
#include <vector>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

typedef int CounterID;

#define goto_if_error(r,msg,label) \
    if (r != TSS2_RC_SUCCESS) { \
        LOG(ERROR) << msg << " Error detail: " << Tss2_RC_Decode(r); \
        goto label;  \
    }

void play_with_TPM();
RSA* createPublicRSA(std::string key);
bool verify_signature(RSA *publicKey, unsigned char *data, int data_size, 
                        unsigned char *sig, int sig_size);
// bool verify_signature(RSA *publicKey, uint8_t *data, int data_size, uint8_t* sig);
int counter_certify(CounterID counter_id, ESYS_CONTEXT *esys_context);
int get_handler_by_counterID(CounterID counter_id, ESYS_CONTEXT *esys_context);
int create_counter(CounterID, ESYS_CONTEXT *esys_context);
int destroy_counter(CounterID, ESYS_CONTEXT *esys_context);

int initialize_tpm();
bool is_nv_defined(uint32_t nv_handle);
TSS2_RC create_nv_counter(uint32_t nv_handle);


//- This func is used to undefine nv counters
int clear_counters(uint32_t index_begin, uint32_t index_end);
//- Used to create counter to faciliate raft testing
int create_counters(std::vector<uint32_t>&);
int create_counters_hybrid(std::vector<uint32_t>&);
int clear_counters(std::vector<uint32_t>&);

void ocall_create_counter(uint32_t* counter_id);
void ocall_increase_counter(uint32_t counter_id);
void ocall_retrieve_counter(uint32_t counter_id, uint8_t* qualification_data,
                            int qual_size, uint8_t* attested_data, 
                            int buffer_size, int* attest_size, uint8_t* sig_data);



//- Performace test
void get_performance(uint32_t index);
void get_performance_sys(uint32_t index);
TSS2_RC create_hybrid_nv_counter(uint32_t nv_handle);
TSS2_RC certify_counter(uint32_t nv_handle);

void esys_session_test(uint32_t counter_index);
