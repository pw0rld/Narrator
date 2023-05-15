SET(HOST_SRC main.cpp
             easylogging++.cc
             tpm_counter.cpp
             sys_tpm_counter.cpp
             tpm_helper.cpp)
# 让easylogging++每个日志文件都覆盖之前的
add_compile_definitions(ELPP_FRESH_LOG_FILE)
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
# set(CMAKE_CXX_STANDARD 11)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
# include_directories(${CMAKE_CURRENT_SOURCE_DIR}/tpm_session_test)

file(GLOB_RECURSE UTIL_SRC "${CMAKE_CURRENT_SOURCE_DIR}/tpm_test_util/*.c"
                           "${CMAKE_CURRENT_SOURCE_DIR}/tpm_test_util/*.cpp" )
file(GLOB_RECURSE TPM_TEST_SRC "${CMAKE_CURRENT_SOURCE_DIR}/tpm_session_test/*.cpp"
                               "${CMAKE_CURRENT_SOURCE_DIR}/tpm_session_test/*.c" )

add_executable(tpm_main ${HOST_SRC} ${UTIL_SRC} ${TPM_TEST_SRC})

include_directories("/usr/local/include/tss2")

target_include_directories(
  tpm_main PRIVATE # Needed for the generated file helloworld_u.h
                          ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(tpm_main 
                        tss2-esys 
                        tss2-sys
                        tss2-mu 
                        tss2-rc
                        tss2-tcti-device
                        ssl
                        crypto)
