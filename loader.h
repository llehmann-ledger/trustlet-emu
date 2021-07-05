#ifndef _LOADER_H
#define	_LOADER_H 1

#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <errno.h>

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
  size_t offset_mem; // Useful ?
};

struct Symbol
{
  char *name;
  void *got;
  void *real_addr;
  int flags;
  struct Symbol *next;
};

struct Trustlet
{
  char *name;
  int nb_segments; // Useful ?
  struct Segment *segments;
  size_t base_addr;
  int nb_symbols; // Useful ?
  struct Symbol *symbols;
};

#endif /* loader.h */