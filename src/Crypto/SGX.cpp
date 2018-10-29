#include "SGX.h"
#include "Platform/Platform.h"

namespace VeraCrypt
{
	static __inline void native_cpuid(unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
	{
		// ecx is often an input as well as an output.

	#if !defined(_MSC_VER)

		asm volatile("cpuid"
			: "=a" (*eax),
			"=b" (*ebx),
			"=c" (*ecx),
			"=d" (*edx)
			: "0" (*eax), "2" (*ecx));

	#else
		int registers[4] = {0,0,0,0};

		__cpuidex(registers, *eax, *ecx);
		*eax = registers[0];
		*ebx = registers[1];
		*ecx = registers[2];
		*edx = registers[3];

	#endif
	}

	short SgxIsEnabled()
	{
		if (SGX_STATUS == 0 || SGX_STATUS == 1)
			return SGX_STATUS;

		unsigned eax, ebx, ecx, edx;
		eax = 1; // processor info and feature bits

		native_cpuid(&eax, &ebx, &ecx, &edx);

		eax = 7;
		ecx = 0;
		native_cpuid(&eax, &ebx, &ecx, &edx);

		//CPUID.(EAX=07H, ECX=0H):EBX.SGX = 1,

		SGX_STATUS = (ebx >> 2) & 0x1;
		return SGX_STATUS;
	}

	sgx_status_t init_enclave(sgx_enclave_id_t* eid)
	{
		sgx_launch_token_t token = {0};
		int updated = 0;
		sgx_status_t ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
		return ret;
	}

	sgx_status_t destroy_enclave(sgx_enclave_id_t eid)
	{
		sgx_status_t ret = sgx_destroy_enclave(eid);
		return ret;
	}

	byte* sgx_seal_data(sgx_enclave_id_t eid, byte *data_in, uint64 data_size, uint64 *sealed_data_size_out)
	{
		if (eid == -1)
		{
			if (DEFAULT_ENCLAVE == -1)
				if (init_enclave(&DEFAULT_ENCLAVE) != SGX_SUCCESS)
					throw SGXError(SRC_POS);
			eid = DEFAULT_ENCLAVE;
		}

		byte *sealed_data;
		uint32_t sealed_data_size;
		sgx_status_t ret = SGX_ERROR_UNEXPECTED;

		ret = ecall_get_sealed_data_size(eid, data_size, &sealed_data_size);

		if (ret != SGX_SUCCESS)
			return NULL;

		sealed_data = (byte*) malloc(sealed_data_size);

		ret = ecall_seal_data(eid, data_in, data_size, sealed_data, sealed_data_size);

		if (ret != SGX_SUCCESS)
		{
			free(sealed_data);
			*sealed_data_size_out = 0;
			return NULL;
		}

		*sealed_data_size_out = sealed_data_size;

		return sealed_data;
	}

	byte* sgx_unseal_data(sgx_enclave_id_t eid, byte *data_in, uint64 data_size, uint64 *unsealed_data_size_out)
	{
		if (eid == -1)
		{
			if (DEFAULT_ENCLAVE == -1)
				if (init_enclave(&DEFAULT_ENCLAVE) != SGX_SUCCESS)
					throw SGXError(SRC_POS);
			eid = DEFAULT_ENCLAVE;
		}

		byte *unsealed_data;
		uint32_t unsealed_data_size;
		sgx_status_t ret = SGX_ERROR_UNEXPECTED;

		ret = ecall_get_unsealed_data_size(eid, data_in, data_size, &unsealed_data_size);

		if (ret != SGX_SUCCESS)
			return NULL;

		unsealed_data = (byte*) malloc(unsealed_data_size);

		ret = ecall_unseal_data(eid, data_in, data_size, unsealed_data, unsealed_data_size);

		if (ret != SGX_SUCCESS)
		{
			free(unsealed_data);
			*unsealed_data_size_out = 0;
			return NULL;
		}

		*unsealed_data_size_out = unsealed_data_size;

		return unsealed_data;
	}

}
