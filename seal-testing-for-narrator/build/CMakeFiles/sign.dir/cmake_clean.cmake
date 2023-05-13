file(REMOVE_RECURSE
  "CMakeFiles/sign"
  "enclave_a_v1/enclave_a_v1.signed"
  "enclave_a_v2/enclave_a_v2.signed"
  "enclave_b/enclave_b.signed"
  "private_a.pem"
  "private_b.pem"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/sign.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
