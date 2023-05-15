#include "easylogging++.h"
#include "tpm_counter.h"
#include "sys_tpm_counter.h"
extern "C" {
#include "tpm_session_test/sys-hmac-auth.int2.h"
}


INITIALIZE_EASYLOGGINGPP
int node_num = 0;
int main() {
    //- Init tpm things before calling enclave.
    if (initialize_tpm() != 0) {
        std::cout << "TPM init error " << std::endl;
        return 0;
    }
    //- Create counter for XPS clusters
    std::vector<uint32_t> create_list;
    //- Create for XPS-i
    int i = 2;
    uint32_t nv_first = 0x01000000 + (i * 0x00001000);
    for (int j = 0; j < 4; j++) {
        create_list.push_back(nv_first + j);
    }
    create_counters(create_list);


    // bool is_defined = is_nv_defined(0x01000001);
    // LOG(INFO) << " is_defined = " << is_defined;
    // create_nv_counter(0x01000000);
    // play_with_TPM();

    // std::vector<uint32_t> create_list;
    // for (int i = 0; i < 1; i++) {
    //     uint32_t nv_first = 0x01000010 + (i * 0x00001000);
    //     for (int j = 0; j < 4; j++) {
    //         create_list.push_back(nv_first + j);
    //     }
    // }
    // create_counters_hybrid(create_list);

    // create_list.push_back(0x01000000);
    // clear_counters(create_list);
    // clear_counters(0x01000000, 0x01003000);
    
    // create_hybrid_nv_counter(0x01000000);
    // get_performance(0x01000010);
    // get_performance_sys(0x01000010);

    // esys_session_test(0x01000000);

    // test_invoke2();


    // sys_init();
    // define_nv_test(0x01000002);
    // increment_nv_test(0x01000002);
    return 0;
}