#include "elf_helper.h"
#include <string.h>

void map_segments(struct Segment *segment_list, int fd) {
  struct Segment *curr = segment_list;

  int prot = PROT_READ | PROT_WRITE;
  int flags = MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS;
  while (curr) {
    if (curr->perm & PF_X)
     prot |= PROT_EXEC;

    curr->mem = mmap(curr->offset_mem + BASE_ADDR_TRUSTLET, curr->size, prot, flags, -1, 0);
    if (curr->mem == MAP_FAILED) {
      perror("Error in mmap segment");
      exit(-1);
    }

    int lseek_result = lseek(fd, curr->offset_file, SEEK_SET);
    if (lseek_result != curr->offset_file) {
      perror("Error in lseek segment");
      exit(-1);
    }

    int read_result = read(fd, curr->mem, curr->size);
    if (read_result != curr->size) {
      perror("Error read segment");
      exit(-1);
    }

    if (curr->perm & PF_X) {
      int mprotect_result = mprotect(curr->mem, curr->size, prot & ~PROT_EXEC);
      if (mprotect_result == -1) {
        perror("Error mprotect segment");
        exit(-1);
      }
    }
    curr = curr->next;
  }
}

struct Trustlet* parse_elf(char* name) {
  int fd = open(name, O_RDONLY);
  struct stat st;

  if (fd == -1) {
    perror("Error in open");
    exit(-1);
  }


  if (fstat(fd,&st) < 0) {
    perror("Error in fstat");
    exit(-1);
  }

  void *elf_header = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (elf_header == MAP_FAILED) {
      perror("Error in mmap ELF file");
      exit(-1);
  }
  struct Trustlet *t_let = calloc(sizeof(struct Trustlet), 1);
  
  // Is that really useful ?
  t_let->name = malloc(strlen(name));
  strcpy(t_let->name, name);

  t_let->symbols = NULL;
  t_let->base_addr = BASE_ADDR_TRUSTLET;

  Elf_Ehdr *eh = (Elf_Ehdr *) elf_header;
  if (!strncmp(eh->e_ident, ELFMAG, SELFMAG)) {
    printf("File is a valid ELF !\n\n");
  } else {
    printf("Invalid file : not an ELF file\n");
    exit(-1);
  }
	switch(eh->e_ident[EI_CLASS])
	{
		case ELFCLASS32:
#ifdef BIT64_SUPPORT
      printf("Trustlet-emu is compiled for 64 bit support only !\n");
      exit(-1);
#endif
			break;
		case ELFCLASS64:
#ifndef BIT64_SUPPORT
      printf("Trustlet-emu is compiled for 32 bit support only !\n");
      exit(-1);
#endif
			break;
		default:
			printf("Invalid Class\n");
      exit(-1);
			break;
	}

  if (eh->e_machine != EM_ARM) {
    printf("Are you seriously trying to load an ELF not compiled for ARM ? GTFO\n");
    exit(-1);
  }

  t_let->segments = calloc(sizeof(struct Segment), 1);
  struct Segment *curr_segment = t_let->segments;  
  Elf_Phdr *e_phdr = (Elf_Phdr* )(elf_header + eh->e_phoff);
  
  t_let->segments->offset_mem = e_phdr[0].p_vaddr; // Physical address needed ?
  printf("Offset mem : 0x%x\n", t_let->segments->offset_mem);
  t_let->segments->offset_file = e_phdr[0].p_offset;
  printf("Offset file : 0x%x\n", t_let->segments->offset_file);
  t_let->segments->size =  e_phdr[0].p_filesz;
  printf("File size : 0x%x\n", t_let->segments->size);
  t_let->segments->type =  e_phdr[0].p_type;
  printf("Type : %d\n", t_let->segments->type);
  t_let->segments->perm =  e_phdr[0].p_flags;
  printf("Flags (perm) : %d\n", t_let->segments->perm);

  for (int i = 1; i < eh->e_phnum; i++) {
    struct Segment *temp = calloc(sizeof(struct Segment), 1);
    temp->offset_mem = e_phdr[i].p_vaddr; // Physical address needed ?
    printf("Offset mem : 0x%x\n", temp->offset_mem);
    temp->offset_file = e_phdr[i].p_offset;
    printf("Offset file : 0x%x\n", temp->offset_file);
    temp->size =  e_phdr[i].p_filesz;
    printf("File size : 0x%x\n", temp->size);
    temp->type =  e_phdr[i].p_type;
    printf("Type : %d\n", temp->type);
    temp->perm =  e_phdr[i].p_flags;
    printf("Flags (perm) : %d\n", temp->perm);

    if (temp->type != PT_NULL) {
      curr_segment->next = temp;
      curr_segment = temp;
    }
  }
  curr_segment->next = NULL;
  map_segments(t_let->segments, fd);

  close(fd);
  return t_let;
}


void init_dynparser(struct Dyn_parser_helper *dyn_p) {
  dyn_p->dt_pltgot = calloc(sizeof(struct Dyn_section), 1);
  dyn_p->dt_hash = calloc(sizeof(struct Dyn_section), 1);
  dyn_p->dt_symtab = calloc(sizeof(struct Dyn_section), 1);
  dyn_p->dt_jmprel = calloc(sizeof(struct Dyn_section), 1);
  dyn_p->dt_rel = calloc(sizeof(struct Dyn_section), 1);
  dyn_p->dt_strtab = calloc(sizeof(struct Dyn_section), 1);
}

struct Dyn_parser_helper* parse_dynamic(void* mem, size_t base_addr) {
  struct Dyn_parser_helper *dyn_p = calloc(sizeof(struct Dyn_parser_helper), 1);;
  init_dynparser(dyn_p);
  Elf_Dyn *curr = ((Elf_Dyn *) mem);
  
  // DT_NULL is always the last entry
  while (curr->d_tag != DT_NULL) {
    switch (curr->d_tag)
    {
    case DT_PLTGOT:
      dyn_p->dt_pltgot->mem = curr->d_val + base_addr;
      printf("DT_PLTGOT: addr %p, real_addr %p\n", curr->d_val, dyn_p->dt_pltgot->mem);
      break;

    case DT_HASH:
      dyn_p->dt_hash->mem = curr->d_val + base_addr;
      printf("DT_HASH: addr %p, real_addr %p\n", curr->d_val, dyn_p->dt_hash->mem);
      // The second Elf_Word in DT_HASH holds the number of entry in DT_SYMTAB
      Elf_Sword nbentry_symtab = *((Elf_Sword*)(dyn_p->dt_hash->mem) + 1);
      printf("Number of entry in DT_SYMTAB: %d\n", nbentry_symtab);
      if (dyn_p->dt_symtab->size == 0) {
        // We did not yet reached DT_SYMENT which holds the size of one entry
        dyn_p->dt_symtab->size = nbentry_symtab;
      } else {
        // We already reached DT_SYMENT which holds the size of one entry
        // Let's multiply it with the number of entry
        dyn_p->dt_symtab->size *= nbentry_symtab;
        printf("DT_SYMTAB total size: 0x%2x\n", dyn_p->dt_symtab->size);
      }
      break;

    case DT_SYMENT:
      // The d_val of DT_SYMENT holds the size of one entry in DT_SYMTAB
      printf("Entry size of DT_SYMTAB: %d\n", curr->d_val);
      if (dyn_p->dt_symtab->size == 0) {
        // We did not yet reached DT_HASH which holds the number of entry
        dyn_p->dt_symtab->size = curr->d_val;
      } else {
        // We already reached DT_HASH which holds the number of entry
        // Let's multiply it with the number of entry
        dyn_p->dt_symtab->size *= curr->d_val;
        printf("DT_SYMTAB total size: 0x%2x\n", dyn_p->dt_symtab->size);
      }
      break;

    case DT_RELSZ:
      dyn_p->dt_rel->size = curr->d_val;
      printf("DT_REL size is: 0x%2x\n", curr->d_val);
      break;

    case DT_PLTRELSZ:
      dyn_p->dt_jmprel->size = curr->d_val;
      printf("DT_JMPREL size is: 0x%2x\n", curr->d_val);
      break;

    case DT_STRSZ:
      dyn_p->dt_strtab->size = curr->d_val;
      printf("DT_STRTAB size is: 0x%2x\n", curr->d_val);
      break;
    
    case DT_SYMTAB:
      dyn_p->dt_symtab->mem = curr->d_val + base_addr;
      printf("DT_SYMTAB: addr %p, real_addr %p\n", curr->d_val, dyn_p->dt_symtab->mem);
      break;
      
    case DT_JMPREL:
      dyn_p->dt_jmprel->mem = curr->d_val + base_addr;
      printf("DT_JMPREL: addr %p, real_addr %p\n", curr->d_val, dyn_p->dt_jmprel->mem);
      break;

    case DT_REL:
      dyn_p->dt_rel->mem = curr->d_val + base_addr;
      printf("DT_REL: addr %p, real_addr %p\n", curr->d_val, dyn_p->dt_rel->mem);
      break;

    case DT_STRTAB:
      dyn_p->dt_strtab->mem = curr->d_val + base_addr;
      printf("DT_STRTAB: addr %p, real_addr %p\n", curr->d_val, dyn_p->dt_strtab->mem);
      break;

    default:
      break;
    }
    curr+=1;
  }
  return dyn_p;
}

struct Symbol* parse_symbols(struct Dyn_section *dt_symtab, struct Dyn_section *dt_strtab, size_t base_addr) {
  struct Symbol *first = calloc(sizeof(struct Symbol), 1);
  struct Symbol *curr_symbol = first;  
  // First symbol always null ?
  Elf_Sym *curr_elf = ((Elf_Sym *) dt_symtab->mem) + 1;

  first->name = malloc(strlen(curr_elf->st_name + dt_strtab->mem));
  strcpy(first->name, curr_elf->st_name + dt_strtab->mem);
  printf("name : %s\n", first->name);
  first->real_addr = curr_elf->st_value;
  if (first->real_addr == NULL) {
    first->flags = 1;
  } else {
    first->real_addr += base_addr;
    first->flags = 0;
  }
  printf("got_addr : %p\n", first->got_addr);
  printf("real_addr : %p\n", first->real_addr);
  printf("external : %d\n\n",  first->flags );

  curr_elf+=1;

  while (curr_elf < dt_symtab->mem + dt_symtab->size) {
    struct Symbol *temp = calloc(sizeof(struct Symbol), 1);
    temp->name = malloc(strlen(curr_elf->st_name + dt_strtab->mem));
    strcpy(temp->name, curr_elf->st_name + dt_strtab->mem);
    printf("name : %s\n", temp->name);
    temp->real_addr = curr_elf->st_value;
    if (temp->real_addr == NULL) {
      temp->flags = 1;
    } else {
      temp->real_addr += base_addr;
      temp->flags = 0;
    }
    printf("got_addr : %p\n", temp->got_addr);
    printf("real_addr : %p\n", temp->real_addr);
    printf("external : %d\n\n",  temp->flags );

    curr_symbol->next = temp;
    curr_symbol = temp;

    curr_elf+=1; 
  }
  curr_symbol->next = NULL;
  return first;
}

//TODO : Refactoring into one single function
struct Symbol* find_symbol_from_real_addr(struct Symbol *sym_list, void* s_addr, size_t base_addr) {
  struct Symbol *res = sym_list;
  while (res) {
    if(res->real_addr == s_addr + base_addr)
      return res;
    else if (res->next != NULL)
      res = res->next;
    else
      return NULL;
  }
}

//TODO : Refactoring into one single function
struct Symbol* find_symbol_from_name(struct Symbol *sym_list, const char* name) {
  struct Symbol *res = sym_list;
  while (res) {
    if(strcmp(res->name, name) == 0)
      return res;
    else if (res->next != NULL)
      res = res->next;
    else
      return NULL;
  }
}

//TODO : Refactoring into one single function
struct Symbol* find_symbol_from_index(struct Symbol *sym_list, int index, size_t base_addr) {
  struct Symbol *res = sym_list;
  int cpt = 1;
  while (res) {
    if(cpt == index)
      return res;
    else if (res->next != NULL)
      res = res->next;
    else
      return NULL;
    cpt++;
  }
}

void parse_rel(struct Symbol *sym_list, struct Dyn_section *dt_rel, size_t base_addr) {
  Elf_Rel *curr = (Elf_Rel *) dt_rel->mem;

  while (curr < dt_rel->mem + dt_rel->size) {
    Elf_Addr *addr_reloc = curr->r_offset + base_addr;
    if (ELF_R_SYM(curr->r_info) == 0) {
      struct Symbol *symbol_reloc = find_symbol_from_real_addr(sym_list, *addr_reloc, base_addr);

      if (symbol_reloc != NULL) {
        printf("Symbol found : %s\n", symbol_reloc->name);
        printf("Symbol GOT address : %p\n", addr_reloc);
        symbol_reloc->got_addr = addr_reloc;
        *addr_reloc += base_addr;
      } else {
        printf("/!\\ Symbol not found at : %p, which came from : %p\n", *addr_reloc, addr_reloc);
        //FIXME : Needs to add a is_mmaped(addr)
        //
        //        if is_mmaped(addr) is TRUE
        //           Addr += Base Addr
        //   
        //        else if addr is (nil)
        //           Stays (nil) ?  
        //        else
        //           ERR SHOULD NOT HAPPENS
      }
    } else {
      struct Symbol *symbol_reloc = find_symbol_from_index(sym_list, ELF_R_SYM(curr->r_info), base_addr);
      printf("Symbol found : %s\n", symbol_reloc->name);
      printf("Symbol GOT address : %p\n", addr_reloc);
      symbol_reloc->got_addr = addr_reloc;
      *addr_reloc += base_addr;
    }
    curr+=1;
  }
}

void parse_jmprel(struct Symbol *sym_list, struct Dyn_section *dt_jmprel, size_t base_addr) {
  Elf_Rel *curr = (Elf_Rel *) dt_jmprel->mem;
  while (curr < dt_jmprel->mem + dt_jmprel->size) {
    Elf_Addr *addr_reloc = curr->r_offset + base_addr;
    struct Symbol *symbol_reloc = find_symbol_from_index(sym_list, ELF_R_SYM(curr->r_info), base_addr);
    if (symbol_reloc != NULL) {
      printf("Symbol found : %s\n", symbol_reloc->name);
      printf("Symbol GOT address : %p\n", addr_reloc);
      symbol_reloc->got_addr = addr_reloc;
    } else {
      printf("Error, we shouldn't get here, we're coming from : %p\n", addr_reloc);
    }
    curr+=1;
  }
}