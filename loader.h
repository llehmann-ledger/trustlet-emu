#ifndef _LOADER_H
#define	_LOADER_H 1

#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <errno.h>

struct 
{
  size_t size;
  void *mem;
} dyn_section;

struct 
{
  struct dyn_section *dt_pltgot;
  struct dyn_section *dt_hash;
  struct dyn_section *dt_symtab;
  struct dyn_section *dt_syment;
  struct dyn_section *dt_jmprel;
  struct dyn_section *dt_pltrelsz;
  struct dyn_section *dt_rel;
  struct dyn_section *dt_relsz;
  struct dyn_section *dt_strtab;
  struct dyn_section *dt_strsize;
} dyn_parser_helper;

struct 
{
  void *mem;
  size_t size;
  int type;
  int perm;
  size_t offset_file;
  size_t offset_mem; // Useful ?
} segment;

struct 
{
  char *name;
  void *got;
  void *real_addr;
  int flags;
  struct symbol *next;
} symbol;

struct 
{
  char *name;
  int nb_segments; // Useful ?
  struct segment *segments;
  size_t base_addr;
  int nb_symbols; // Useful ?
  struct symbol *symbols;
} trustlet;

#endif /* loader.h */