#include "Enclave_u.h"
#include <errno.h>

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

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t ecall_get_sealed_data_size(sgx_enclave_id_t eid, uint32_t data_size, uint32_t* sealed_data_size)
{
	sgx_status_t status;
	ms_ecall_get_sealed_data_size_t ms;
	ms.ms_data_size = data_size;
	ms.ms_sealed_data_size = sealed_data_size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_seal_data(sgx_enclave_id_t eid, uint8_t* data, uint32_t data_size, uint8_t* sealed_data, uint32_t sealed_data_size)
{
	sgx_status_t status;
	ms_ecall_seal_data_t ms;
	ms.ms_data = data;
	ms.ms_data_size = data_size;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_data_size = sealed_data_size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_get_unsealed_data_size(sgx_enclave_id_t eid, uint8_t* sealed_data, uint32_t sealed_data_size, uint32_t* unsealed_data_size)
{
	sgx_status_t status;
	ms_ecall_get_unsealed_data_size_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_data_size = sealed_data_size;
	ms.ms_unsealed_data_size = unsealed_data_size;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_unseal_data(sgx_enclave_id_t eid, uint8_t* sealed_data, uint32_t sealed_data_size, uint8_t* unsealed_data, uint32_t unsealed_data_size)
{
	sgx_status_t status;
	ms_ecall_unseal_data_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_data_size = sealed_data_size;
	ms.ms_unsealed_data = unsealed_data;
	ms.ms_unsealed_data_size = unsealed_data_size;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

