#ifndef _LOADER_H
#define	_LOADER_H 1

#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <errno.h>

// Arbitrary, could be anything code will still works
#define BASE_ADDR_TRUSTLET     ((void *)0x00100000)

// Arbitrary, could be anything code will still works
#define BASE_ADDR_CMNLIB     ((void *)0x10000000)

// Arbitrary, could be anything code will still works
#define HEAP_ADDR     ((void *)0x20000000)

struct Dyn_section
{
  size_t size;
  void *mem;
};

struct Dyn_parser_helper
{
  struct Dyn_section *dt_pltgot;
  struct Dyn_section *dt_hash;
  struct Dyn_section *dt_symtab;
  struct Dyn_section *dt_jmprel;
  struct Dyn_section *dt_rel;
  struct Dyn_section *dt_strtab;
};

struct Segment
{
  void *mem;
  size_t size;
  int type;
  int perm;
  size_t offset_file;
  size_t offset_mem;
  struct Segment *next;
};

struct Symbol
{
  char *name;
  void *got_addr;
  void *real_addr;
  int flags;
  struct Symbol *next;
};

struct Trustlet
{
  struct Segment *segments;
  size_t base_addr;
  struct Symbol *symbols;
  size_t e_entry;
};

#endif /* loader.h */