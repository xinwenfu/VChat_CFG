/*
Disable Security Warnings!
This should be done before
any include directives
*/
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>

#include <windows.h>
#include <Memoryapi.h>
#include <psapi.h>

#include <stdint.h>
#include <intrin.h>

/* Preprocessor Directive to control program */
//#define E1 1
//#define E2 1
#define E3 1
//#define EDIT_WHTLIST

/* Preprocessor Directive */
#define CFG_CALL_TARGET_INVALID (0x00000000) // This should be anything that is not 1

/* Forward Declerations */
void good_func(void);
void bad_func(void);
void edit_cfg(void);


/*
Define a variable to store function pointers
this is done to make the code less confusing!

This is a function pointer for functions 
which take no arguments and have a return of
void.
*/
typedef void (*funcionpointer)();


/* Structure to enforce alignment */
struct bstruct {
	char bad_buff[18];
	char buff[1];
	/*
	  19 bytes, 1 byte of padding
	  to preserve 4 byte default bounds.
	  Need an extra char to ensure
	  we overflow properly...

	  If /Zp1 enabled they will be adjacent
	*/
	funcionpointer x;
};

/* Arbitrary Global Variable that is always 0 */
const int check = 0;

int main(int argc, char* argv) {
	/* Allocate Structure on the Stack */
	struct bstruct ex;

	/* Set the function pointer to `good_func` */
	ex.x = good_func;


#ifdef EDIT_WHTLIST
	/* Remove good_func and bad_func from the CFG whitelist */
	edit_cfg();
#endif


	/* Output Adderesses of the Buffers and Objects in the Struct */
	printf("Bad_buffer: %p\nSmall_buffer: % p\nFunction_Pointer: % p\n", &ex.bad_buff, &ex.buff, &ex.x);

	
#ifdef E1
	/* 
	Overflow the orginal value into the function pointer 
	This is more of a control case.
	*/
	sprintf(ex.bad_buff, "AA%c%c%c%c", (char)((int)good_func), (char)(((int)good_func) >> 8), (char)(((int)good_func) >> 16), (char)(((int)good_func) >> 24));
	printf("Resulting Bad Str: %d%d%d%d\nOriginal Address: %p\n", (unsigned)ex.bad_buff[1], (unsigned)ex.bad_buff[2], (unsigned)ex.bad_buff[3], (unsigned)ex.bad_buff[4], good_func);
	strcpy(ex.buff, ex.bad_buff);
#elif E2
	/* Overflow address of the bad function */
	sprintf(ex.bad_buff, "AA%c%c%c%c", (char)((int)bad_func), (char)(((int)bad_func) >> 8), (char)(((int)bad_func) >> 16), (char)(((int)bad_func) >> 24));
	printf("Resulting Bad Str: %d%d%d%d\nOriginal Address: %p\n", (unsigned)ex.bad_buff[1], (unsigned)ex.bad_buff[2], (unsigned)ex.bad_buff[3], (unsigned)ex.bad_buff[4], good_func);
	strcpy(ex.buff, ex.bad_buff);
#elif E3
	/* Overflow offset into the bad function to perform code that would otherwise not happen */
	sprintf(ex.bad_buff, "AA%c%c%c%c", (char)((int)bad_func + 0x00000023), (char)(((int)bad_func + 0x00000023) >> 8), (char)(((int)bad_func + 0x00000023) >> 16), (char)(((int)bad_func + 0x00000023) >> 24));
	printf("Resulting Bad Str: %d%d%d%d\nOriginal Address: %p\n", (unsigned)ex.bad_buff[1], (unsigned)ex.bad_buff[2], (unsigned)ex.bad_buff[3], (unsigned)ex.bad_buff[4], good_func);
	strcpy(ex.buff, ex.bad_buff);
#endif

	ex.x(); // Need NX Compat enabled

	return 1;
}

static void good_func() {
	/*
	We add a series of instructions and function calls to
	pad out the function, so we can jump to a point
	greater than 8 bytes in!
	*/

	// https://learn.microsoft.com/en-us/cpp/intrinsics/nop?view=msvc-170
	// NOP sled used from https://blog.trailofbits.com/2016/12/27/lets-talk-about-cfi-microsoft-edition/
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();
	__nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop(); __nop();

	printf("Hello World\n");


	if (check == 1) {
		printf("This is never supposed to print\n");
		bad_func();
	}
	else {
		// https://learn.microsoft.com/en-us/shows/inside/c0000005
		printf("This is always supposed to print\n");
	}

	return;
}

static void bad_func() {
	printf("Goodby World from Bad Func");
	if (check == 1) {
		printf("This is never supposed to print\n");
	}
	else {
		printf("This is always supposed to print\n");
	}
	return;
}

void edit_cfg(void) {
	// https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-moduleinfo
	MODULEINFO mi;
	//https://learn.microsoft.com/en-us/windows/win32/memory/-cfg-call-target-info
	CFG_CALL_TARGET_INFO call_dests[2];

	// Get the base address and size of the currently loaded module
	// so that we can figure out where each function entry point is
	// in relation to the start of the allocation of this process image
	// https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmoduleinformation
	if (0 == GetModuleInformation(GetCurrentProcess(),
		GetModuleHandle(NULL),
		&mi,
		sizeof(mi))) {
		printf("Could not get the base address for this module\n");
		exit(-1);
	}

	printf("Base of loaded image: %p\n", mi.lpBaseOfDll);
	printf("Size of loaded image: %x\n", mi.SizeOfImage);

	// remove float_arg from the valid CFG mapping
	call_dests[0].Flags = CFG_CALL_TARGET_INVALID;
	call_dests[0].Offset = (ULONG_PTR)(good_func)-(ULONG_PTR)(mi.lpBaseOfDll);

	call_dests[1].Flags = CFG_CALL_TARGET_INVALID;
	call_dests[1].Offset = (ULONG_PTR)(bad_func)-(ULONG_PTR)(mi.lpBaseOfDll);


	// update valid CFG targets
	if (TRUE != SetProcessValidCallTargets(
		GetCurrentProcess(),
		mi.lpBaseOfDll,
		mi.SizeOfImage,
		2,
		call_dests)) {
		printf("WARNING: Failed on SetProcessValidCallTargets: %08x\n", GetLastError());
	}
}
