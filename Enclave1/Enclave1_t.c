#include "Enclave1_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_sizeOfSealData(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sizeOfSealData_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sizeOfSealData_t* ms = SGX_CAST(ms_sizeOfSealData_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = sizeOfSealData();


	return status;
}

static sgx_status_t SGX_CDECL sgx_seal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_seal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_seal_t* ms = SGX_CAST(ms_seal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_sealedData = ms->ms_sealedData;
	uint32_t _tmp_seal_data_size = ms->ms_seal_data_size;
	size_t _len_sealedData = _tmp_seal_data_size;
	sgx_sealed_data_t* _in_sealedData = NULL;
	char* _tmp_debug = ms->ms_debug;
	uint8_t _tmp_debug_size = ms->ms_debug_size;
	size_t _len_debug = _tmp_debug_size;
	char* _in_debug = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealedData, _len_sealedData);
	CHECK_UNIQUE_POINTER(_tmp_debug, _len_debug);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealedData != NULL && _len_sealedData != 0) {
		if ((_in_sealedData = (sgx_sealed_data_t*)malloc(_len_sealedData)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealedData, 0, _len_sealedData);
	}
	if (_tmp_debug != NULL && _len_debug != 0) {
		if ((_in_debug = (char*)malloc(_len_debug)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_debug, 0, _len_debug);
	}

	seal(_in_sealedData, _tmp_seal_data_size, _in_debug, _tmp_debug_size);
err:
	if (_in_sealedData) {
		if (memcpy_s(_tmp_sealedData, _len_sealedData, _in_sealedData, _len_sealedData)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_sealedData);
	}
	if (_in_debug) {
		if (memcpy_s(_tmp_debug, _len_debug, _in_debug, _len_debug)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_debug);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_encryptText(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encryptText_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encryptText_t* ms = SGX_CAST(ms_encryptText_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_plainText = ms->ms_plainText;
	size_t _tmp_length = ms->ms_length;
	size_t _len_plainText = _tmp_length;
	char* _in_plainText = NULL;
	char* _tmp_cipher = ms->ms_cipher;
	size_t _tmp_len_cipher = ms->ms_len_cipher;
	size_t _len_cipher = _tmp_len_cipher;
	char* _in_cipher = NULL;
	sgx_sealed_data_t* _tmp_sealed = ms->ms_sealed;
	uint32_t _tmp_sealed_Size = ms->ms_sealed_Size;
	size_t _len_sealed = _tmp_sealed_Size;
	sgx_sealed_data_t* _in_sealed = NULL;
	char* _tmp_debug = ms->ms_debug;
	uint8_t _tmp_debug_size = ms->ms_debug_size;
	size_t _len_debug = _tmp_debug_size;
	char* _in_debug = NULL;

	CHECK_UNIQUE_POINTER(_tmp_plainText, _len_plainText);
	CHECK_UNIQUE_POINTER(_tmp_cipher, _len_cipher);
	CHECK_UNIQUE_POINTER(_tmp_sealed, _len_sealed);
	CHECK_UNIQUE_POINTER(_tmp_debug, _len_debug);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_plainText != NULL && _len_plainText != 0) {
		_in_plainText = (char*)malloc(_len_plainText);
		if (_in_plainText == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_plainText, _len_plainText, _tmp_plainText, _len_plainText)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cipher != NULL && _len_cipher != 0) {
		if ((_in_cipher = (char*)malloc(_len_cipher)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cipher, 0, _len_cipher);
	}
	if (_tmp_sealed != NULL && _len_sealed != 0) {
		_in_sealed = (sgx_sealed_data_t*)malloc(_len_sealed);
		if (_in_sealed == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed, _len_sealed, _tmp_sealed, _len_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_debug != NULL && _len_debug != 0) {
		if ((_in_debug = (char*)malloc(_len_debug)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_debug, 0, _len_debug);
	}

	encryptText(_in_plainText, _tmp_length, _in_cipher, _tmp_len_cipher, _in_sealed, _tmp_sealed_Size, _in_debug, _tmp_debug_size);
err:
	if (_in_plainText) free(_in_plainText);
	if (_in_cipher) {
		if (memcpy_s(_tmp_cipher, _len_cipher, _in_cipher, _len_cipher)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_cipher);
	}
	if (_in_sealed) free(_in_sealed);
	if (_in_debug) {
		if (memcpy_s(_tmp_debug, _len_debug, _in_debug, _len_debug)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_debug);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_decryptText(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_decryptText_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_decryptText_t* ms = SGX_CAST(ms_decryptText_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_encMessageIn = ms->ms_encMessageIn;
	size_t _tmp_len = ms->ms_len;
	size_t _len_encMessageIn = _tmp_len;
	char* _in_encMessageIn = NULL;
	char* _tmp_decMessageOut = ms->ms_decMessageOut;
	size_t _tmp_lenOut = ms->ms_lenOut;
	size_t _len_decMessageOut = _tmp_lenOut;
	char* _in_decMessageOut = NULL;
	sgx_sealed_data_t* _tmp_sealed = ms->ms_sealed;
	uint32_t _tmp_sealed_Size = ms->ms_sealed_Size;
	size_t _len_sealed = _tmp_sealed_Size;
	sgx_sealed_data_t* _in_sealed = NULL;
	char* _tmp_debug = ms->ms_debug;
	uint8_t _tmp_debug_size = ms->ms_debug_size;
	size_t _len_debug = _tmp_debug_size;
	char* _in_debug = NULL;

	CHECK_UNIQUE_POINTER(_tmp_encMessageIn, _len_encMessageIn);
	CHECK_UNIQUE_POINTER(_tmp_decMessageOut, _len_decMessageOut);
	CHECK_UNIQUE_POINTER(_tmp_sealed, _len_sealed);
	CHECK_UNIQUE_POINTER(_tmp_debug, _len_debug);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encMessageIn != NULL && _len_encMessageIn != 0) {
		_in_encMessageIn = (char*)malloc(_len_encMessageIn);
		if (_in_encMessageIn == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_encMessageIn, _len_encMessageIn, _tmp_encMessageIn, _len_encMessageIn)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_decMessageOut != NULL && _len_decMessageOut != 0) {
		if ((_in_decMessageOut = (char*)malloc(_len_decMessageOut)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_decMessageOut, 0, _len_decMessageOut);
	}
	if (_tmp_sealed != NULL && _len_sealed != 0) {
		_in_sealed = (sgx_sealed_data_t*)malloc(_len_sealed);
		if (_in_sealed == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed, _len_sealed, _tmp_sealed, _len_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_debug != NULL && _len_debug != 0) {
		if ((_in_debug = (char*)malloc(_len_debug)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_debug, 0, _len_debug);
	}

	decryptText(_in_encMessageIn, _tmp_len, _in_decMessageOut, _tmp_lenOut, _in_sealed, _tmp_sealed_Size, _in_debug, _tmp_debug_size);
err:
	if (_in_encMessageIn) free(_in_encMessageIn);
	if (_in_decMessageOut) {
		if (memcpy_s(_tmp_decMessageOut, _len_decMessageOut, _in_decMessageOut, _len_decMessageOut)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_decMessageOut);
	}
	if (_in_sealed) free(_in_sealed);
	if (_in_debug) {
		if (memcpy_s(_tmp_debug, _len_debug, _in_debug, _len_debug)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_debug);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_sizeOfSealData, 0},
		{(void*)(uintptr_t)sgx_seal, 0},
		{(void*)(uintptr_t)sgx_encryptText, 0},
		{(void*)(uintptr_t)sgx_decryptText, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[5][4];
} g_dyn_entry_table = {
	5,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	ocalloc_size += (cpuinfo != NULL) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	ocalloc_size += (waiters != NULL) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
