#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t ecall_get_sealed_data_size(sgx_enclave_id_t eid, uint32_t data_size, uint32_t* sealed_data_size);
sgx_status_t ecall_seal_data(sgx_enclave_id_t eid, uint8_t* data, uint32_t data_size, uint8_t* sealed_data, uint32_t sealed_data_size);
sgx_status_t ecall_get_unsealed_data_size(sgx_enclave_id_t eid, uint8_t* sealed_data, uint32_t sealed_data_size, uint32_t* unsealed_data_size);
sgx_status_t ecall_unseal_data(sgx_enclave_id_t eid, uint8_t* sealed_data, uint32_t sealed_data_size, uint8_t* unsealed_data, uint32_t unsealed_data_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
