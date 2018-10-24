
# SGX_SDK ?= /home/rcampra/Documents/linux-sgx-master/linux/installer/bin/sgxsdk
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

######## App Settings ########
App_C_Files := App/Lib_ocalls.c App/App.c
App_C_Flags := -fPIC -Wno-attributes -IInclude -IApp -I$(SGX_SDK)/include
App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -lsgx_urts_sim -lpthread -lsgx_uae_service_sim
App_C_Objects := $(App_C_Files:.c=.o)
App_Name := app

######## Enclave Settings ########
Enclave_C_Files := Lib_ecalls.c
Enclave_C_Flags := -nostdinc -fvisibility=hidden -fpie -fstack-protector -IInclude -IEnclave \
	-I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++

Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -lsgx_tservice_sim -Wl,--end-group \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0
	
Enclave_C_Objects := $(Enclave_Cpp_Files:.c=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := ../../Main/enclave.signed.so
Enclave_Config_File := Enclave.config.xml

.PHONY: all run

all: $(Signed_Enclave_Name)

run: all

######## App Objects ########
Enclave_u.c: $(SGX_EDGER8R) Enclave.edl
	$(SGX_EDGER8R) --untrusted Enclave.edl --search-path $(SGX_SDK)/include

Enclave_u.o: Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@

#App/Lib_ocalls.o: App/Lib_ocalls.c
#	@$(CC) $(App_C_Flags) -c $< -o $@
	
#App/App.o: App/App.c
#	@$(CC) $(App_C_Flags) -c $< -o $@

#$(App_Name): App/Enclave_u.o App/App.o App/Lib_ocalls.o
#	@$(CC) $^ -o $@ $(App_Link_Flags)

######## Enclave Objects ########
Enclave_t.c: $(SGX_EDGER8R) Enclave.edl
	$(SGX_EDGER8R) --trusted Enclave.edl --search-path $(SGX_SDK)/include

Enclave_t.o: Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@

Lib_ecalls.o: Lib_ecalls.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@

$(Enclave_Name): Enclave_t.o Lib_ecalls.o
	@$(CC) $^ -o $@ $(Enclave_Link_Flags)

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)

.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_C_Objects) ../Enclave_u.* $(Enclave_C_Objects) Enclave_t.*
