#include <stdbool.h>
#include <stdio.h>
#include <getopt.h>
#include <stdarg.h>
#include "loader.h"
#include "elf_helper.h"
#include "hook_functions.h"

bool VERBOSE = false;

struct Trustlet * map_trustlet(const char *path, size_t base_addr) {
  struct Trustlet *t_let = parse_elf(path, base_addr);
  struct Segment *dyn_seg = t_let->segments;
  bool stop = false;
  // Find dynamic segment
  while (dyn_seg && !stop) {
    if (dyn_seg->type == PT_DYNAMIC) {
      stop = true;
    } else {
      dyn_seg = dyn_seg->next;
    }
  }
  
  if (!dyn_seg) {
    log_message(DEBUG_MSG, "No dynamic segment. Stopping.\n");
    return t_let;
  }

  t_let->e_entry += base_addr;
  log_message(DEBUG_MSG, "Dynamic parsing step:\n\n");
  struct Dyn_parser_helper *res = parse_dynamic(dyn_seg->mem, base_addr);
  
  log_message(DEBUG_MSG, "Symbols parsing step:\n\n");
  t_let->symbols = parse_symbols(res->dt_symtab, res->dt_strtab, base_addr);
  
  log_message(DEBUG_MSG, "Parsing DT_REL step:\n\n");
  parse_rel(t_let, res->dt_rel, base_addr);
  
  log_message(DEBUG_MSG, "Parsing DT_JMPREL step:\n\n");
  parse_jmprel(t_let->symbols, res->dt_jmprel, base_addr);

  log_message(INFO_MSG, "Done.\n");
  return t_let;
}

void log_message(int level, char *message, ...) {
  va_list myargs;
  va_start(myargs, message);
  switch (level)
  {
    case ERR_MSG:
    case INFO_MSG:
      vprintf(message, myargs);
      break;
    case DEBUG_MSG:
      if (VERBOSE)
        vprintf(message, myargs);
      break;
    default:
      break;
  }
  va_end(myargs);  
    int ret;
}

void print_help() {
  log_message(INFO_MSG, "Usage: trustlet-emu -t TRUSTLET_PATH -c CMNLIB_PATH [OPTION]\n\n");
  log_message(INFO_MSG, "Valid OPTION are:\n");
  log_message(INFO_MSG, "  -v\t\t Verbose output.\n");
  log_message(INFO_MSG, "  -h\t\t Print this help message.\n");
  exit(-1);
}
int main(int argc, char *argv[]) {

  int opt = 0;
  const char *trustlet_path = NULL;
  const char *cmnlib_path = NULL;

  while ((opt = getopt(argc, argv, "t:c:vh")) != -1) {
    switch(opt) {
      case 't':
        trustlet_path = optarg;
        break;
      case 'c':
        cmnlib_path = optarg;
        break;
      case 'v':
        VERBOSE = true;
        break;
      case 'h':
        print_help();
        break;
      case '?':
        print_help();
       break;
    }
  }

  if (!trustlet_path || !cmnlib_path)
    print_help();

  // TODO: Support 32/64 bits
  log_message(INFO_MSG, "\n[+] Load trustlet in memory\n\n");
  struct Trustlet *t_let = map_trustlet(trustlet_path, BASE_ADDR_TRUSTLET);
  log_message(INFO_MSG, "\n[+] Load cmnlib in memory\n\n");
  struct Trustlet *t_lib = map_trustlet(cmnlib_path, BASE_ADDR_CMNLIB);

  // Hook some functions that we are interested in
  // TODO : Support 32/64 bits
  // MAYBE : Get functions names to hook from arguments ?
  log_message(INFO_MSG, "\n[+] Hook functions\n\n");
  hook_functions(t_lib->symbols);

  // Dynamic link of symbols
  log_message(INFO_MSG, "\n[+] Link symbols dynamically\n\n");
  link_symbols(t_let->symbols, t_lib->symbols);

  // Seek to entry point
  struct Segment *code_seg = t_let->segments;
  bool stop = false;
  // Find dynamic segment
  while (code_seg && !stop) {
    if (code_seg->type == PT_LOAD && (code_seg->perm & (PF_X))) {
      stop = true;
    } else {
      code_seg = code_seg->next;
    }
  }

  if (!code_seg) {
    log_message(ERR_MSG, "No code segment. Stopping.\n");
    return -1;
  }

  Elf_Addr entry_point = 0;
  struct Symbol *celf_invoke = find_symbol_from_name(t_let->symbols, "CElfFile_invoke");
  if (!celf_invoke) {
    entry_point = t_let->e_entry;
  } else {
    entry_point = celf_invoke->real_addr;
  }

  // Allocate heap
  // What is a good value for heap_size ?
  size_t t_heap_size = 0x10000;
  void *t_heap = mmap(HEAP_ADDR, t_heap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
  if (t_heap == MAP_FAILED) {
    perror("Error in mmap stack");
    exit(-1);
  }
  struct Symbol *app_heap_base = find_symbol_from_name(t_let->symbols, "app_heap_base");
  struct Symbol *app_heap_limit = find_symbol_from_name(t_let->symbols, "app_heap_limit");

  *((Elf_Addr *)(app_heap_base->got_addr)) = (Elf_Addr)(t_heap);
  app_heap_base->real_addr = t_heap;
  *((Elf_Addr *)(app_heap_limit->got_addr)) = (Elf_Addr)(t_heap + t_heap_size);
  app_heap_limit->real_addr = t_heap + t_heap_size;

  // Allocate stack
  // What value to use as stack size ?
  size_t t_stack_size = 0x10000;
  register void *sp asm ("sp");

  struct Symbol *app_stack_base = find_symbol_from_name(t_let->symbols, "app_stack_base");
  struct Symbol *app_stack_limit = find_symbol_from_name(t_let->symbols, "app_stack_limit");

  *((Elf_Addr *)(app_stack_base->got_addr)) = (Elf_Addr)(sp);
  app_stack_base->real_addr = sp;
  *((Elf_Addr *)(app_stack_limit->got_addr)) = (Elf_Addr)(sp + t_stack_size);
  app_stack_limit->real_addr = sp + t_stack_size;

  log_message(INFO_MSG, "\n[+] Start trustlet execution\n\n");
  // TODO : Support 32/64 bits
  asm volatile(
               "mov r9, %0\n"
               "blx  %1\n"
               "bkpt\n"
               :
              : "r"(code_seg->mem), "r"(BASE_ADDR_CMNLIB + 0x391d) // Debug : To test qsee_log from cmnlib
//               : "r"(code_seg->mem), "r"(BASE_ADDR_TRUSTLET + 0x169) // Debug : To test qsee_log from htc_drmprov trustlet
//               : "r"(code_seg->mem), "r"(entry_point)
               : "r9");

  return 0;
}    