# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
include_directories(${Boost_INCLUDE_DIRS})

add_custom_command(
  OUTPUT attestation_u.h attestation_u.c attestation_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/attestation.edl
  COMMAND
    openenclave::oeedger8r --untrusted
    ${CMAKE_SOURCE_DIR}/attestation.edl --search-path ${OE_INCLUDEDIR}
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)


add_executable(attestation_host
               host.cpp ${CMAKE_CURRENT_BINARY_DIR}/attestation_u.c
               ../host/system_init.cpp
               ../host/state_requests.cpp
               ../host/network/MyServer.cpp
               ../host/network/get_ip.cpp
               ../host/network/process_buffer.cpp
               ../host/network/misc.cpp
               ../host/network/messages.cpp
               ../host/enclave_operation.cpp
               )
target_include_directories(
  attestation_host
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../ # For common/shared.h
          ${CMAKE_CURRENT_BINARY_DIR}
          ${Boost_LIBRARIES})

if (WIN32)
  add_dcap_client_target(attestation_dcap_target)
  add_dependencies(attestation_host attestation_dcap_target)
  copy_oedebugrt_target(attestation_oedebugrt_target)
  add_dependencies(attestation_host attestation_oedebugrt_target)
endif ()

find_package(Boost REQUIRED COMPONENTS thread)
target_link_libraries(attestation_host openenclave::oehost Boost::thread)
