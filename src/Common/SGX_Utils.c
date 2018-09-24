
#ifndef _INCLUDED_SGX_UTILS
#define _INCLUDED_SGX_UTILS

#if defined(__cplusplus)
extern "C"
{
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#endif

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

int SgxIsEnabled()
{
	unsigned eax, ebx, ecx, edx;
	eax = 1; // processor info and feature bits 

	native_cpuid(&eax, &ebx, &ecx, &edx);

	eax = 7;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);

	//CPUID.(EAX=07H, ECX=0H):EBX.SGX = 1,
	return  (ebx >> 2) & 0x1;
}

#if defined(__cplusplus)
}
#endif

#endif
