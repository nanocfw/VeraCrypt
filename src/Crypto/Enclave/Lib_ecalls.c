#include "sgx_tseal.h"
#include "Enclave_t.h" // Gerado pelo Edger8r

void ecall_get_sealed_data_size(uint32_t data_size, uint32_t *sealed_data_size) {
    *sealed_data_size = sgx_calc_sealed_data_size(0, data_size);
}

void ecall_seal_data(uint8_t *data, uint32_t data_size, uint8_t *sealed_data, uint32_t sealed_data_size) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_seal_data(0, NULL, data_size, data, sealed_data_size, (sgx_sealed_data_t*)sealed_data);
}

void ecall_get_unsealed_data_size(uint8_t *sealed_data, uint32_t sealed_data_size, uint32_t *unsealed_data_size) {
    *unsealed_data_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);
}

void ecall_unseal_data(uint8_t *sealed_data, uint32_t sealed_data_size, uint8_t *unsealed_data, uint32_t unsealed_data_size) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, 0, unsealed_data, &unsealed_data_size);
}
