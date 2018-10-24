#ifndef _INCLUDED_SGX_UTILS
#define _INCLUDED_SGX_UTILS

#include "sgx_eid.h"
#include "sgx_urts.h"
#include "Enclave_u.h" // Gerado pelo Edger8r

#if defined(__cplusplus)
extern "C"
{
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#endif

static __inline void native_cpuid(unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx);

static short SGX_STATUS = 2;//0 indisponível, 1 disponível, 2 não verificado

short SgxIsEnabled();

#define ENCLAVE_FILENAME "/home/marciano/VeraCrypt/src/Main/enclave.signed.so"

sgx_status_t init_enclave(sgx_enclave_id_t* eid);
uint8_t* sgx_seal_data(sgx_enclave_id_t eid, uint8_t *data_in,  uint32_t data_size, uint32_t *sealed_data_size_out);
uint8_t* sgx_unseal_data(sgx_enclave_id_t eid, uint8_t *data_in, uint32_t data_size);

#if defined(__cplusplus)
}
#endif

#endif

