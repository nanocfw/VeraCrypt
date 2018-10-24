#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_get_sealed_data_size(uint32_t data_size, uint32_t* sealed_data_size);
void ecall_seal_data(uint8_t* data, uint32_t data_size, uint8_t* sealed_data, uint32_t sealed_data_size);
void ecall_get_unsealed_data_size(uint8_t* sealed_data, uint32_t sealed_data_size, uint32_t* unsealed_data_size);
void ecall_unseal_data(uint8_t* sealed_data, uint32_t sealed_data_size, uint8_t* unsealed_data, uint32_t unsealed_data_size);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
