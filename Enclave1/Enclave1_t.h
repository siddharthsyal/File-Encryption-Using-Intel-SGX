#ifndef ENCLAVE1_T_H__
#define ENCLAVE1_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tseal.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

uint32_t sizeOfSealData(void);
void seal(sgx_sealed_data_t* sealedData, uint32_t seal_data_size, char* debug, uint8_t debug_size);
void encryptText(char* plainText, size_t length, char* cipher, size_t len_cipher, sgx_sealed_data_t* sealed, uint32_t sealed_Size, char* debug, uint8_t debug_size);
void decryptText(char* encMessageIn, size_t len, char* decMessageOut, size_t lenOut, sgx_sealed_data_t* sealed, uint32_t sealed_Size, char* debug, uint8_t debug_size);

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
