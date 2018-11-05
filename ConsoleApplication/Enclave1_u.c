#include "Enclave1_u.h"
#include <errno.h>

typedef struct ms_sizeOfSealData_t {
	uint32_t ms_retval;
} ms_sizeOfSealData_t;

typedef struct ms_seal_t {
	sgx_sealed_data_t* ms_sealedData;
	uint32_t ms_seal_data_size;
	char* ms_debug;
	uint8_t ms_debug_size;
} ms_seal_t;

typedef struct ms_encryptText_t {
	char* ms_plainText;
	size_t ms_length;
	char* ms_cipher;
	size_t ms_len_cipher;
	sgx_sealed_data_t* ms_sealed;
	uint32_t ms_sealed_Size;
	char* ms_debug;
	uint8_t ms_debug_size;
} ms_encryptText_t;

typedef struct ms_decryptText_t {
	char* ms_encMessageIn;
	size_t ms_len;
	char* ms_decMessageOut;
	size_t ms_lenOut;
	sgx_sealed_data_t* ms_sealed;
	uint32_t ms_sealed_Size;
	char* ms_debug;
	uint8_t ms_debug_size;
} ms_decryptText_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave1_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave1_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave1_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave1_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave1_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[5];
} ocall_table_Enclave1 = {
	5,
	{
		(void*)(uintptr_t)Enclave1_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave1_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave1_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave1_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave1_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t sizeOfSealData(sgx_enclave_id_t eid, uint32_t* retval)
{
	sgx_status_t status;
	ms_sizeOfSealData_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave1, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t seal(sgx_enclave_id_t eid, sgx_sealed_data_t* sealedData, uint32_t seal_data_size, char* debug, uint8_t debug_size)
{
	sgx_status_t status;
	ms_seal_t ms;
	ms.ms_sealedData = sealedData;
	ms.ms_seal_data_size = seal_data_size;
	ms.ms_debug = debug;
	ms.ms_debug_size = debug_size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave1, &ms);
	return status;
}

sgx_status_t encryptText(sgx_enclave_id_t eid, char* plainText, size_t length, char* cipher, size_t len_cipher, sgx_sealed_data_t* sealed, uint32_t sealed_Size, char* debug, uint8_t debug_size)
{
	sgx_status_t status;
	ms_encryptText_t ms;
	ms.ms_plainText = plainText;
	ms.ms_length = length;
	ms.ms_cipher = cipher;
	ms.ms_len_cipher = len_cipher;
	ms.ms_sealed = sealed;
	ms.ms_sealed_Size = sealed_Size;
	ms.ms_debug = debug;
	ms.ms_debug_size = debug_size;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave1, &ms);
	return status;
}

sgx_status_t decryptText(sgx_enclave_id_t eid, char* encMessageIn, size_t len, char* decMessageOut, size_t lenOut, sgx_sealed_data_t* sealed, uint32_t sealed_Size, char* debug, uint8_t debug_size)
{
	sgx_status_t status;
	ms_decryptText_t ms;
	ms.ms_encMessageIn = encMessageIn;
	ms.ms_len = len;
	ms.ms_decMessageOut = decMessageOut;
	ms.ms_lenOut = lenOut;
	ms.ms_sealed = sealed;
	ms.ms_sealed_Size = sealed_Size;
	ms.ms_debug = debug;
	ms.ms_debug_size = debug_size;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave1, &ms);
	return status;
}

