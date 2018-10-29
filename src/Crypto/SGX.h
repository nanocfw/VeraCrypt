#ifndef _INCLUDED_SGX_UTILS
#define _INCLUDED_SGX_UTILS

#include "sgx_eid.h"
#include "sgx_urts.h"
#include "Enclave_u.h" // Gerado pelo Edger8r
#include "Common/Tcdefs.h"

#if defined(_MSC_VER)
#include <intrin.h>
#endif

static __inline void native_cpuid(unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx);

static short SGX_STATUS = 2;//0 indisponível, 1 disponível, 2 não verificado
static sgx_enclave_id_t DEFAULT_ENCLAVE = -1;

short SgxIsEnabled();

#define ENCLAVE_FILENAME "/home/marciano/VeraCrypt/src/Main/enclave.signed.so"

namespace VeraCrypt
{
	sgx_status_t init_enclave(sgx_enclave_id_t* eid);
	sgx_status_t destroy_enclave(sgx_enclave_id_t eid);
	byte* sgx_seal_data(sgx_enclave_id_t eid, byte *data_in,  uint64 data_size, uint64 *sealed_data_size_out);
	byte* sgx_unseal_data(sgx_enclave_id_t eid, byte *data_in, uint64 data_size, uint64 *unsealed_data_size_out);
}

#endif

