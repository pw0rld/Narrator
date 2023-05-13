/*
 *  This file is auto generated by oeedger8r. DO NOT EDIT.
 */
#ifndef EDGER8R_DATASEALING_U_H
#define EDGER8R_DATASEALING_U_H

#include <openenclave/host.h>

#include "datasealing_args.h"

OE_EXTERNC_BEGIN

oe_result_t oe_create_datasealing_enclave(
    const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    const oe_enclave_setting_t* settings,
    uint32_t setting_count,
    oe_enclave_t** enclave);

/**** ECALL prototypes. ****/
oe_result_t seal_data(
    oe_enclave_t* enclave,
    int* _retval,
    int sealPolicy,
    unsigned char* opt_mgs,
    size_t opt_msg_len,
    unsigned char* data,
    size_t data_size,
    sealed_data_t** sealed_data,
    size_t* sealed_data_size);

oe_result_t unseal_data(
    oe_enclave_t* enclave,
    int* _retval,
    sealed_data_t* sealed_data,
    size_t sealed_data_size,
    unsigned char** data,
    size_t* data_size);

oe_result_t oe_get_sgx_report_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    const void* opt_params,
    size_t opt_params_size,
    sgx_report_t* report);

oe_result_t oe_get_report_v2_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint32_t flags,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size);

oe_result_t oe_verify_local_report_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);

oe_result_t oe_sgx_init_context_switchless_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    oe_host_worker_context_t* host_worker_contexts,
    uint64_t num_host_workers);

oe_result_t oe_sgx_switchless_enclave_worker_thread_ecall(
    oe_enclave_t* enclave,
    oe_enclave_worker_context_t* context);

/**** OCALL prototypes. ****/
oe_host_fd_t oe_syscall_epoll_create1_ocall(int flags);

int oe_syscall_epoll_wait_ocall(
    int64_t epfd,
    struct oe_epoll_event* events,
    unsigned int maxevents,
    int timeout);

int oe_syscall_epoll_wake_ocall(void);

int oe_syscall_epoll_ctl_ocall(
    int64_t epfd,
    int op,
    int64_t fd,
    struct oe_epoll_event* event);

int oe_syscall_epoll_close_ocall(oe_host_fd_t epfd);

oe_host_fd_t oe_syscall_open_ocall(
    const char* pathname,
    int flags,
    oe_mode_t mode);

ssize_t oe_syscall_read_ocall(
    oe_host_fd_t fd,
    void* buf,
    size_t count);

ssize_t oe_syscall_write_ocall(
    oe_host_fd_t fd,
    const void* buf,
    size_t count);

ssize_t oe_syscall_readv_ocall(
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size);

ssize_t oe_syscall_writev_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size);

oe_off_t oe_syscall_lseek_ocall(
    oe_host_fd_t fd,
    oe_off_t offset,
    int whence);

ssize_t oe_syscall_pread_ocall(
    oe_host_fd_t fd,
    void* buf,
    size_t count,
    oe_off_t offset);

ssize_t oe_syscall_pwrite_ocall(
    oe_host_fd_t fd,
    const void* buf,
    size_t count,
    oe_off_t offset);

int oe_syscall_close_ocall(oe_host_fd_t fd);

int oe_syscall_flock_ocall(
    oe_host_fd_t fd,
    int operation);

int oe_syscall_fsync_ocall(oe_host_fd_t fd);

int oe_syscall_fdatasync_ocall(oe_host_fd_t fd);

oe_host_fd_t oe_syscall_dup_ocall(oe_host_fd_t oldfd);

uint64_t oe_syscall_opendir_ocall(const char* name);

int oe_syscall_readdir_ocall(
    uint64_t dirp,
    struct oe_dirent* entry);

void oe_syscall_rewinddir_ocall(uint64_t dirp);

int oe_syscall_closedir_ocall(uint64_t dirp);

int oe_syscall_stat_ocall(
    const char* pathname,
    struct oe_stat_t* buf);

int oe_syscall_fstat_ocall(
    oe_host_fd_t fd,
    struct oe_stat_t* buf);

int oe_syscall_access_ocall(
    const char* pathname,
    int mode);

int oe_syscall_link_ocall(
    const char* oldpath,
    const char* newpath);

int oe_syscall_unlink_ocall(const char* pathname);

int oe_syscall_rename_ocall(
    const char* oldpath,
    const char* newpath);

int oe_syscall_truncate_ocall(
    const char* path,
    oe_off_t length);

int oe_syscall_ftruncate_ocall(
    oe_host_fd_t fd,
    oe_off_t length);

int oe_syscall_mkdir_ocall(
    const char* pathname,
    oe_mode_t mode);

int oe_syscall_rmdir_ocall(const char* pathname);

int oe_syscall_fcntl_ocall(
    oe_host_fd_t fd,
    int cmd,
    uint64_t arg,
    uint64_t argsize,
    void* argout);

int oe_syscall_ioctl_ocall(
    oe_host_fd_t fd,
    uint64_t request,
    uint64_t arg,
    uint64_t argsize,
    void* argout);

int oe_syscall_poll_ocall(
    struct oe_host_pollfd* host_fds,
    oe_nfds_t nfds,
    int timeout);

int oe_syscall_kill_ocall(
    int pid,
    int signum);

int oe_syscall_close_socket_ocall(oe_host_fd_t sockfd);

oe_host_fd_t oe_syscall_socket_ocall(
    int domain,
    int type,
    int protocol);

int oe_syscall_shutdown_sockets_device_ocall(oe_host_fd_t sockfd);

int oe_syscall_socketpair_ocall(
    int domain,
    int type,
    int protocol,
    oe_host_fd_t sv[2]);

int oe_syscall_connect_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen);

oe_host_fd_t oe_syscall_accept_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out);

int oe_syscall_bind_ocall(
    oe_host_fd_t sockfd,
    const struct oe_sockaddr* addr,
    oe_socklen_t addrlen);

int oe_syscall_listen_ocall(
    oe_host_fd_t sockfd,
    int backlog);

ssize_t oe_syscall_recvmsg_ocall(
    oe_host_fd_t sockfd,
    void* msg_name,
    oe_socklen_t msg_namelen,
    oe_socklen_t* msg_namelen_out,
    void* msg_iov_buf,
    size_t msg_iovlen,
    size_t msg_iov_buf_size,
    void* msg_control,
    size_t msg_controllen,
    size_t* msg_controllen_out,
    int flags);

ssize_t oe_syscall_sendmsg_ocall(
    oe_host_fd_t sockfd,
    const void* msg_name,
    oe_socklen_t msg_namelen,
    void* msg_iov_buf,
    size_t msg_iovlen,
    size_t msg_iov_buf_size,
    const void* msg_control,
    size_t msg_controllen,
    int flags);

ssize_t oe_syscall_recv_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags);

ssize_t oe_syscall_recvfrom_ocall(
    oe_host_fd_t sockfd,
    void* buf,
    size_t len,
    int flags,
    struct oe_sockaddr* src_addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out);

ssize_t oe_syscall_send_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags);

ssize_t oe_syscall_sendto_ocall(
    oe_host_fd_t sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct oe_sockaddr* dest_addr,
    oe_socklen_t addrlen);

ssize_t oe_syscall_recvv_ocall(
    oe_host_fd_t fd,
    void* iov_buf,
    int iovcnt,
    size_t iov_buf_size);

ssize_t oe_syscall_sendv_ocall(
    oe_host_fd_t fd,
    const void* iov_buf,
    int iovcnt,
    size_t iov_buf_size);

int oe_syscall_shutdown_ocall(
    oe_host_fd_t sockfd,
    int how);

int oe_syscall_setsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    const void* optval,
    oe_socklen_t optlen);

int oe_syscall_getsockopt_ocall(
    oe_host_fd_t sockfd,
    int level,
    int optname,
    void* optval,
    oe_socklen_t optlen_in,
    oe_socklen_t* optlen_out);

int oe_syscall_getsockname_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out);

int oe_syscall_getpeername_ocall(
    oe_host_fd_t sockfd,
    struct oe_sockaddr* addr,
    oe_socklen_t addrlen_in,
    oe_socklen_t* addrlen_out);

int oe_syscall_getaddrinfo_open_ocall(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    uint64_t* handle);

int oe_syscall_getaddrinfo_read_ocall(
    uint64_t handle,
    int* ai_flags,
    int* ai_family,
    int* ai_socktype,
    int* ai_protocol,
    oe_socklen_t ai_addrlen_in,
    oe_socklen_t* ai_addrlen,
    struct oe_sockaddr* ai_addr,
    size_t ai_canonnamelen_in,
    size_t* ai_canonnamelen,
    char* ai_canonname);

int oe_syscall_getaddrinfo_close_ocall(uint64_t handle);

int oe_syscall_getnameinfo_ocall(
    const struct oe_sockaddr* sa,
    oe_socklen_t salen,
    char* host,
    oe_socklen_t hostlen,
    char* serv,
    oe_socklen_t servlen,
    int flags);

int oe_syscall_nanosleep_ocall(
    struct oe_timespec* req,
    struct oe_timespec* rem);

int oe_syscall_clock_nanosleep_ocall(
    oe_clockid_t clockid,
    int flag,
    struct oe_timespec* req,
    struct oe_timespec* rem);

int oe_syscall_getpid_ocall(void);

int oe_syscall_getppid_ocall(void);

int oe_syscall_getpgrp_ocall(void);

unsigned int oe_syscall_getuid_ocall(void);

unsigned int oe_syscall_geteuid_ocall(void);

unsigned int oe_syscall_getgid_ocall(void);

unsigned int oe_syscall_getegid_ocall(void);

int oe_syscall_getpgid_ocall(int pid);

int oe_syscall_getgroups_ocall(
    size_t size,
    unsigned int* list);

int oe_syscall_uname_ocall(struct oe_utsname* buf);

oe_result_t oe_get_supported_attester_format_ids_ocall(format_ids_t* format_ids);

oe_result_t oe_get_qetarget_info_ocall(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    sgx_target_info_t* target_info);

oe_result_t oe_get_quote_ocall(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const sgx_report_t* sgx_report,
    void* quote,
    size_t quote_size,
    size_t* quote_size_out);

oe_result_t oe_get_quote_verification_collateral_ocall(
    uint8_t fmspc[6],
    uint8_t collateral_provider,
    void* tcb_info,
    size_t tcb_info_size,
    size_t* tcb_info_size_out,
    void* tcb_info_issuer_chain,
    size_t tcb_info_issuer_chain_size,
    size_t* tcb_info_issuer_chain_size_out,
    void* pck_crl,
    size_t pck_crl_size,
    size_t* pck_crl_size_out,
    void* root_ca_crl,
    size_t root_ca_crl_size,
    size_t* root_ca_crl_size_out,
    void* pck_crl_issuer_chain,
    size_t pck_crl_issuer_chain_size,
    size_t* pck_crl_issuer_chain_size_out,
    void* qe_identity,
    size_t qe_identity_size,
    size_t* qe_identity_size_out,
    void* qe_identity_issuer_chain,
    size_t qe_identity_issuer_chain_size,
    size_t* qe_identity_issuer_chain_size_out);

oe_result_t oe_verify_quote_ocall(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const void* p_quote,
    uint32_t quote_size,
    const time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_info_size,
    void* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint32_t* p_supplemental_data_size_out,
    uint32_t collateral_version,
    const void* p_tcb_info,
    uint32_t tcb_info_size,
    const void* p_tcb_info_issuer_chain,
    uint32_t tcb_info_issuer_chain_size,
    const void* p_pck_crl,
    uint32_t pck_crl_size,
    const void* p_root_ca_crl,
    uint32_t root_ca_crl_size,
    const void* p_pck_crl_issuer_chain,
    uint32_t pck_crl_issuer_chain_size,
    const void* p_qe_identity,
    uint32_t qe_identity_size,
    const void* p_qe_identity_issuer_chain,
    uint32_t qe_identity_issuer_chain_size);

oe_result_t oe_sgx_get_cpuid_table_ocall(
    void* cpuid_table_buffer,
    size_t cpuid_table_buffer_size);

oe_result_t oe_sgx_backtrace_symbols_ocall(
    oe_enclave_t* oe_enclave,
    const uint64_t* buffer,
    size_t size,
    void* symbols_buffer,
    size_t symbols_buffer_size,
    size_t* symbols_buffer_size_out);

void oe_sgx_thread_wake_wait_ocall(
    oe_enclave_t* oe_enclave,
    uint64_t waiter_tcs,
    uint64_t self_tcs);

void oe_sgx_wake_switchless_worker_ocall(oe_host_worker_context_t* context);

void oe_sgx_sleep_switchless_worker_ocall(oe_enclave_worker_context_t* context);

OE_EXTERNC_END

#endif // EDGER8R_DATASEALING_U_H
