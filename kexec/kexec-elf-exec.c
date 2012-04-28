#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include "elf.h"
#include <boot/elf_boot.h>
#include "kexec.h"
#include "kexec-elf.h"

static const int probe_debug = 0;

int build_elf_exec_info(const char *buf, off_t len, struct mem_ehdr *ehdr,
				uint32_t flags)
{
	struct mem_phdr *phdr, *end_phdr;
	int result;
	result = build_elf_info(buf, len, ehdr, flags);
	if (result < 0) {
		return result;
	}
	if ((ehdr->e_type != ET_EXEC) && (ehdr->e_type != ET_DYN) &&
	    (ehdr->e_type != ET_CORE)) {
		/* not an ELF executable */
		if (probe_debug) {
			fprintf(stderr, "Not ELF type ET_EXEC or ET_DYN\n");
		}
		return -1;
	}
	if (!ehdr->e_phdr) {
		/* No program header */
		fprintf(stderr, "No ELF program header\n");
		return -1; 
	}
	end_phdr = &ehdr->e_phdr[ehdr->e_phnum];
	for(phdr = ehdr->e_phdr; phdr != end_phdr; phdr++) {
		/* Kexec does not support loading interpreters.
		 * In addition this check keeps us from attempting
		 * to kexec ordinay executables.
		 */
		if (phdr->p_type == PT_INTERP) {
			fprintf(stderr, "Requires an ELF interpreter\n");
			return -1;
		}
	}

	return 0;
}


int elf_exec_load(struct mem_ehdr *ehdr, struct kexec_info *info)
{
	unsigned long base;
	int result, l;
	size_t i;

	if (!ehdr->e_phdr) {
		fprintf(stderr, "No program header?\n");
		result = -1;
		goto out;
	}

	/* If I have a dynamic executable find it's size
	 * and then find a location for it in memory.
	 */
	base = 0;
	if (ehdr->e_type == ET_DYN) {
		unsigned long first, last, align;
		first = ULONG_MAX;
		last  = 0;
		align = 0;
		for(i = 0; i < ehdr->e_phnum; i++) {
			unsigned long start, stop;
			struct mem_phdr *phdr;
			phdr = &ehdr->e_phdr[i];
			if ((phdr->p_type != PT_LOAD) ||
				(phdr->p_memsz == 0))
			{
				continue;
			}
			start = phdr->p_paddr;
			stop  = start + phdr->p_memsz;
			if (first > start) {
				first = start;
			}
			if (last < stop) {
				last = stop;
			}
			if (align < phdr->p_align) {
				align = phdr->p_align;
			}
		}
		/* If I can't use the default paddr find a new
		 * hole for the dynamic executable.
		 */
		if (!valid_memory_range(info, first, last)) {
			unsigned long hole;
			hole = locate_hole(info,
				last - first + 1, align, 
				0, elf_max_addr(ehdr), 1);
			if (hole == ULONG_MAX) {
				result = -1;
				goto out;
			}
			/* Base is the value that when added
			 * to any virtual address in the file
			 * yields it's load virtual address.
			 */
			base = hole - first;
		}

	}
	
//	char *relocs = "/root/git/mklinux/arch/x86/boot/compressed/vmlinux.relocs";
	char *relocs = "/boot/vmlinux.relocs";
	char *relocs_buf;
	off_t relocs_size;
	long *relocs_array;
	long __page_offset = 0xc0000000;
	int relocs_num = 0;
	int relocs_offset = 0x2000000; // TODO rework here base on mem_min
	
	if (relocs_offset) {
	  relocs_buf = slurp_file (relocs, &relocs_size);
	  relocs_num = relocs_size / sizeof(long); relocs_num--;
	  relocs_array = ((long*) relocs_buf) +1;
	  printf("relocs buffer %p size %ld num %d (__page_offset 0x%08lx)\n", 
		 relocs_buf, relocs_size, relocs_num, __page_offset);
	  printf("relocs buffer 0x%lx 0x%lx - 0x%lx 0x%lx\n", 
		 relocs_array[0], relocs_array[1], relocs_array[(relocs_num -2)], relocs_array[(relocs_num -1)]);
	}
	
	/* Read in the PT_LOAD segments */
	printf("elf_exec_load: segments are %d\n", ehdr->e_phnum);
	for(i = 0; i < ehdr->e_phnum; i++) {
		struct mem_phdr *phdr;
		size_t size;
		phdr = &ehdr->e_phdr[i];
		printf("elf_exec_load: segment %d p_type %d p_filesz %lld p_data %p p_paddr 0x%08llx p_memsz 0x%08llx\n",
		       i, phdr->p_type, phdr->p_filesz, phdr->p_data, phdr->p_paddr, phdr->p_memsz);
		
		if (phdr->p_type != PT_LOAD) {
			continue;
		}
		size = phdr->p_filesz;
		if (size > phdr->p_memsz) {
			size = phdr->p_memsz;
		}
		
		if (mem_min) // TODO rework on that considering relocation, crashkernel, etc.
		  if (!base) // TODO rework
		    base = mem_min - phdr->p_paddr; // TODO rework

		if (relocs_offset) {
			int stats=0;
			//for every entry in the relocation array if does fit in the area apply the relocation
			for (l=0; l<relocs_num; l++) {
				long relocs_location = (relocs_array[l]-__page_offset);
				if ( (phdr->p_paddr <= relocs_location) 
				  && ((relocs_location < (phdr->p_paddr + phdr->p_memsz))) ) {
					long * addr = (long *) ((long)phdr->p_data + (relocs_location-(long)(phdr->p_paddr)));
					*addr += relocs_offset;
					stats++;
				}
			}
			printf("relocs: replaced %d absolute addresses\n", stats);
		}
		  
		add_segment(info,
			phdr->p_data, size,
			phdr->p_paddr + base, phdr->p_memsz);
	}

	/* Update entry point to reflect new load address*/
	ehdr->e_entry += base;

	result = 0;
 out:
	return result;
}

void elf_exec_build_load(struct kexec_info *info, struct mem_ehdr *ehdr, 
	const char *buf, off_t len, uint32_t flags)
{
	int result;
	/* Parse the Elf file */
	result = build_elf_exec_info(buf, len, ehdr, flags);
	if (result < 0) {
		die("ELF exec parse failed\n");
	}

	/* Load the Elf data */
	result = elf_exec_load(ehdr, info);
	if (result < 0) {
		die("ELF exec load failed\n");
	}
}
