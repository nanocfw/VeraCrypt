#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_get_sealed_data_size_t {
	uint32_t ms_data_size;
	uint32_t* ms_sealed_data_size;
} ms_ecall_get_sealed_data_size_t;

typedef struct ms_ecall_seal_data_t {
	uint8_t* ms_data;
	uint32_t ms_data_size;
	uint8_t* ms_sealed_data;
	uint32_t ms_sealed_data_size;
} ms_ecall_seal_data_t;

typedef struct ms_ecall_get_unsealed_data_size_t {
	uint8_t* ms_sealed_data;
	uint32_t ms_sealed_data_size;
	uint32_t* ms_unsealed_data_size;
} ms_ecall_get_unsealed_data_size_t;

typedef struct ms_ecall_unseal_data_t {
	uint8_t* ms_sealed_data;
	uint32_t ms_sealed_data_size;
	uint8_t* ms_unsealed_data;
	uint32_t ms_unsealed_data_size;
} ms_ecall_unseal_data_t;

static sgx_status_t SGX_CDECL sgx_ecall_get_sealed_data_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_sealed_data_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_sealed_data_size_t* ms = SGX_CAST(ms_ecall_get_sealed_data_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint32_t* _tmp_sealed_data_size = ms->ms_sealed_data_size;
	size_t _len_sealed_data_size = sizeof(uint32_t);
	uint32_t* _in_sealed_data_size = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data_size, _len_sealed_data_size);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data_size != NULL && _len_sealed_data_size != 0) {
		if ((_in_sealed_data_size = (uint32_t*)malloc(_len_sealed_data_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data_size, 0, _len_sealed_data_size);
	}

	ecall_get_sealed_data_size(ms->ms_data_size, _in_sealed_data_size);
err:
	if (_in_sealed_data_size) {
		memcpy(_tmp_sealed_data_size, _in_sealed_data_size, _len_sealed_data_size);
		free(_in_sealed_data_size);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_seal_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_seal_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_seal_data_t* ms = SGX_CAST(ms_ecall_seal_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_data = ms->ms_data;
	uint32_t _tmp_data_size = ms->ms_data_size;
	size_t _len_data = _tmp_data_size;
	uint8_t* _in_data = NULL;
	uint8_t* _tmp_sealed_data = ms->ms_sealed_data;
	uint32_t _tmp_sealed_data_size = ms->ms_sealed_data_size;
	size_t _len_sealed_data = _tmp_sealed_data_size;
	uint8_t* _in_sealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_data != NULL && _len_data != 0) {
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_data, _tmp_data, _len_data);
	}
	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ((_in_sealed_data = (uint8_t*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}

	ecall_seal_data(_in_data, _tmp_data_size, _in_sealed_data, _tmp_sealed_data_size);
err:
	if (_in_data) free(_in_data);
	if (_in_sealed_data) {
		memcpy(_tmp_sealed_data, _in_sealed_data, _len_sealed_data);
		free(_in_sealed_data);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_unsealed_data_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_unsealed_data_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_unsealed_data_size_t* ms = SGX_CAST(ms_ecall_get_unsealed_data_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_data = ms->ms_sealed_data;
	uint32_t _tmp_sealed_data_size = ms->ms_sealed_data_size;
	size_t _len_sealed_data = _tmp_sealed_data_size;
	uint8_t* _in_sealed_data = NULL;
	uint32_t* _tmp_unsealed_data_size = ms->ms_unsealed_data_size;
	size_t _len_unsealed_data_size = sizeof(uint32_t);
	uint32_t* _in_unsealed_data_size = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_unsealed_data_size, _len_unsealed_data_size);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		_in_sealed_data = (uint8_t*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sealed_data, _tmp_sealed_data, _len_sealed_data);
	}
	if (_tmp_unsealed_data_size != NULL && _len_unsealed_data_size != 0) {
		if ((_in_unsealed_data_size = (uint32_t*)malloc(_len_unsealed_data_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_unsealed_data_size, 0, _len_unsealed_data_size);
	}

	ecall_get_unsealed_data_size(_in_sealed_data, _tmp_sealed_data_size, _in_unsealed_data_size);
err:
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_unsealed_data_size) {
		memcpy(_tmp_unsealed_data_size, _in_unsealed_data_size, _len_unsealed_data_size);
		free(_in_unsealed_data_size);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_unseal_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_unseal_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_unseal_data_t* ms = SGX_CAST(ms_ecall_unseal_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_data = ms->ms_sealed_data;
	uint32_t _tmp_sealed_data_size = ms->ms_sealed_data_size;
	size_t _len_sealed_data = _tmp_sealed_data_size;
	uint8_t* _in_sealed_data = NULL;
	uint8_t* _tmp_unsealed_data = ms->ms_unsealed_data;
	uint32_t _tmp_unsealed_data_size = ms->ms_unsealed_data_size;
	size_t _len_unsealed_data = _tmp_unsealed_data_size;
	uint8_t* _in_unsealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_unsealed_data, _len_unsealed_data);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		_in_sealed_data = (uint8_t*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sealed_data, _tmp_sealed_data, _len_sealed_data);
	}
	if (_tmp_unsealed_data != NULL && _len_unsealed_data != 0) {
		if ((_in_unsealed_data = (uint8_t*)malloc(_len_unsealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_unsealed_data, 0, _len_unsealed_data);
	}

	ecall_unseal_data(_in_sealed_data, _tmp_sealed_data_size, _in_unsealed_data, _tmp_unsealed_data_size);
err:
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_unsealed_data) {
		memcpy(_tmp_unsealed_data, _in_unsealed_data, _len_unsealed_data);
		free(_in_unsealed_data);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_get_sealed_data_size, 0},
		{(void*)(uintptr_t)sgx_ecall_seal_data, 0},
		{(void*)(uintptr_t)sgx_ecall_get_unsealed_data_size, 0},
		{(void*)(uintptr_t)sgx_ecall_unseal_data, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


