#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <errno.h>

// Not used for now
#define QSEECOM_ALIGN_SIZE	0x40
#define QSEECOM_ALIGN_MASK	(QSEECOM_ALIGN_SIZE - 1)
#define QSEECOM_ALIGN(x)	\
	((x + QSEECOM_ALIGN_SIZE) & (~QSEECOM_ALIGN_MASK))

// Arbitrary
#define BASE_ADDR_TRUSTLET     ((void *)0x000000)

// htc_drmprov : Read Execute
#define PROV_SEGMENT1_SIZE   0x0370c
#define PROV_SEGMENT1_OFFSET_FILE 0x003000
#define PROV_SEGMENT1_OFFSET_MEM BASE_ADDR_TRUSTLET + 0x0000000
#define PROV_SEGMENT1_OFFSET_ENTRY_POINT PROV_SEGMENT1_OFFSET_MEM + 0x1954

// htc_drmprov : Read Write
#define PROV_SEGMENT2_SIZE   0x00075
#define PROV_SEGMENT2_OFFSET_FILE 0x00670c
#define PROV_SEGMENT2_OFFSET_MEM BASE_ADDR_TRUSTLET + 0x00004000

// htc_drmprov : Read Write
#define PROV_SEGMENT3_SIZE   0x00808
#define PROV_SEGMENT3_OFFSET_FILE 0x006788
#define PROV_SEGMENT3_OFFSET_MEM BASE_ADDR_TRUSTLET + 0x00005000

// htc_drmprov : Read Write
#define PROV_SEGMENT4_SIZE   0x0010c
#define PROV_SEGMENT4_OFFSET_FILE 0x006f90
#define PROV_SEGMENT4_OFFSET_MEM BASE_ADDR_TRUSTLET + 0x00006000

// htc_drmprov : Read Write
#define PROV_SEGMENT5_SIZE   0x01083
#define PROV_SEGMENT5_OFFSET_FILE 0x00709c
#define PROV_SEGMENT5_OFFSET_MEM BASE_ADDR_TRUSTLET + 0x00007000

/*
** TODO: Not hardcode address, size, etc
**       Detect 32/64 bits
**       Apply relocs correctly
*/
int map_trustlet(const char* name, void* t_code, void* t_data) {

  int fd_t = open(name, O_RDONLY);
  
  if (fd_t == -1) {
    printf("fail open(\"%s\")", name);
    return -1;
  }

  // Segment 1
  int flags = MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS;
  int prot = PROT_READ | PROT_EXEC | PROT_WRITE;
  t_code = mmap(PROV_SEGMENT1_OFFSET_MEM, PROV_SEGMENT1_SIZE, prot, flags, -1, 0);
  if (t_code == MAP_FAILED) {
    printf("Error mapping PROV_SEGMENT1 : %s",  strerror(errno));
    return -1;
  }

  int lseek_result = lseek(fd_t, PROV_SEGMENT1_OFFSET_FILE, SEEK_SET);
  if (lseek_result != PROV_SEGMENT1_OFFSET_FILE) {
    printf("Error lseek PROV_SEGMENT1 : %s, offset : %d",  strerror(errno), lseek_result);
    return -1;   
  }

  int read_result = read(fd_t, t_code, PROV_SEGMENT1_SIZE);
  if (read_result != PROV_SEGMENT1_SIZE) {
    printf("Error read PROV_SEGMENT1 : %s, offset : %d",  strerror(errno), read_result);
    return -1;   
  }

  int mprotect_result = mprotect(t_code, PROV_SEGMENT1_SIZE, PROT_READ | PROT_EXEC);
  if (mprotect_result == -1) {
    printf("Error mprotect PROV_SEGMENT1 : %s",  strerror(errno));
    return -1;   
  }

  // Segment 2
  prot = PROT_READ | PROT_WRITE;
  t_data = mmap(PROV_SEGMENT2_OFFSET_MEM, PROV_SEGMENT2_SIZE, prot, flags, -1, 0);
  if (t_data == MAP_FAILED) {
    printf("Error mapping PROV_SEGMENT2 : %s",  strerror(errno));
    return -1;
  }

  lseek_result = lseek(fd_t, PROV_SEGMENT2_OFFSET_FILE, SEEK_SET);
  if (lseek_result != PROV_SEGMENT2_OFFSET_FILE) {
    printf("Error lseek PROV_SEGMENT2 : %s, offset : %d",  strerror(errno), lseek_result);
    return -1;   
  }

  read_result = read(fd_t, t_data, PROV_SEGMENT2_SIZE);
  if (read_result != PROV_SEGMENT2_SIZE) {
    printf("Error read PROV_SEGMENT2 : %s, offset : %d",  strerror(errno), read_result);
    return -1;   
  }

  // Segment 3
  void *p3 = mmap(PROV_SEGMENT3_OFFSET_MEM, PROV_SEGMENT3_SIZE, prot, flags, -1, 0);
  if (p3 == MAP_FAILED) {
    printf("Error mapping PROV_SEGMENT3 : %s",  strerror(errno));
    return -1;
  }

  lseek_result = lseek(fd_t, PROV_SEGMENT3_OFFSET_FILE, SEEK_SET);
  if (lseek_result != PROV_SEGMENT3_OFFSET_FILE) {
    printf("Error lseek PROV_SEGMENT3 : %s, offset : %d",  strerror(errno), lseek_result);
    return -1;   
  }

  read_result = read(fd_t, p3, PROV_SEGMENT3_SIZE);
  if (read_result != PROV_SEGMENT3_SIZE) {
    printf("Error read PROV_SEGMENT3 : %s, offset : %d",  strerror(errno), read_result);
    return -1;   
  }
  // Segment 4
  void *p4 = mmap(PROV_SEGMENT4_OFFSET_MEM, PROV_SEGMENT4_SIZE, prot, flags, -1, 0);
  if (p4 == MAP_FAILED) {
    printf("Error mapping PROV_SEGMENT4 : %s",  strerror(errno));
    return -1;
  }

  lseek_result = lseek(fd_t, PROV_SEGMENT4_OFFSET_FILE, SEEK_SET);
  if (lseek_result != PROV_SEGMENT4_OFFSET_FILE) {
    printf("Error lseek PROV_SEGMENT4 : %s, offset : %d",  strerror(errno), lseek_result);
    return -1;   
  }

  read_result = read(fd_t, p4, PROV_SEGMENT4_SIZE);
  if (read_result != PROV_SEGMENT4_SIZE) {
    printf("Error read PROV_SEGMENT4 : %s, offset : %d",  strerror(errno), read_result);
    return -1;   
  }

  // Segment 5
  void *p5 = mmap(PROV_SEGMENT5_OFFSET_MEM, PROV_SEGMENT5_SIZE, prot, flags, -1, 0);
  if (p5 == MAP_FAILED) {
    printf("Error mapping PROV_SEGMENT5 : %s",  strerror(errno));
    return -1;
  }

  lseek_result = lseek(fd_t, PROV_SEGMENT5_OFFSET_FILE, SEEK_SET);
  if (lseek_result != PROV_SEGMENT5_OFFSET_FILE) {
    printf("Error lseek PROV_SEGMENT5 : %s, offset : %d",  strerror(errno), lseek_result);
    return -1;   
  }

  read_result = read(fd_t, p5, PROV_SEGMENT5_SIZE);
  if (read_result != PROV_SEGMENT5_SIZE) {
    printf("Error read PROV_SEGMENT5 : %s, offset : %d",  strerror(errno), read_result);
    return -1;   
  }

    //Debug
    size_t temp = PROV_SEGMENT4_OFFSET_MEM + 0x10000; // A la ghidra, for easy comparaison
    printf("%x:", temp);
    for (int i = 0; i < PROV_SEGMENT4_SIZE; i ++) {
        if (i != 0 && i % 4 == 0) {
         putchar('\n');
         temp+=4;
         printf("%x:", temp);
        }
        printf(" %2x", ((char *)p4)[i]);
    }
    putchar('\n');
}

// Arbitrary
#define BASE_ADDR_CMNLIB     ((void *)0x000000)

// cmnlib : Read execute ?
#define CMNLIB_SEGMENT1_SIZE   0x54000 // ?
#define CMNLIB_SEGMENT1_OFFSET_FILE 0x003000
#define CMNLIB_SEGMENT1_OFFSET_MEM BASE_ADDR_CMNLIB + 0x00007000

/*
** TODO
*/
int map_cmnlib(const char* name) {

}

int main(int argc, char *argv[]) {

  void* t_code;
  void* t_data;

  // TODO : Get name from argv
  map_trustlet("htc_drmprov", t_code, t_data);

  // TODO : map_cmnlib

  // Seek to entry point
  // FIXME : move it to map_trustlet ?
  t_code = t_code + (size_t) PROV_SEGMENT1_OFFSET_ENTRY_POINT;

  void (*f)(unsigned long *);
  f = (void *)((unsigned long)t_code | 1);
  asm volatile(
               "mov r9, %0\n"
               "blx  %1\n"
               "bkpt\n"
               :
               : "r"(t_data), "r"(f)
               : "r9");

 return 0;

}    