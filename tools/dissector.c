/*
 * dissector.c - Coloured ELF files dissector
 * By Alejandro Hernandez <nitr0us>
 *
 * Supported archs: x86 / x86_64
 *
 * No security in mind (No boundary checkings)
 * If a malformed ELF is supplied, it'll definitely segfault
 *
 * $gcc dissector.c -o dissector -Wall
 *
 * Mexico
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>

//#ifdef	COLOURS
#define RED	"\033[31m"
#define WHITE	"\033[01m"
#define YELLOW	"\033[33m"
#define RESET	"\033[00m"
//#else
//#define RED	""
//#define WHITE	""
//#define YELLOW	"\033[33m"
//#define RESET	""
//#endif

/*** 32 - 64 BITS COMPAT ***/
#if defined(__i386__)		// x86
#define Elf_Half Elf32_Half
#define Elf_Word Elf32_Word
#define Elf_Sword Elf32_Sword
#define Elf_Xword Elf32_Xword
#define Elf_Sxword Elf32_Sxword
#define Elf_Addr Elf32_Addr
#define Elf_Off Elf32_Off
#define Elf_Section Elf32_Section
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym Elf32_Sym
#define Elf_Rel Elf32_Rel
#define Elf_Rela Elf32_Rela
#define Elf_Phdr Elf32_Phdr
#define Elf_Dyn Elf32_Dyn
#define Elf_Nhdr Elf32_Nhdr

#define ELF_ST_TYPE ELF32_ST_TYPE
#define ELF_ST_BIND ELF32_ST_BIND
#define ELF_ST_VISIBILITY ELF32_ST_VISIBILITY

#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM

#define DEC "%d"
#define HEX "%.8x"

#define SPACE	""

#elif defined(__x86_64__)	// x86_64
#define Elf_Half Elf64_Half
#define Elf_Word Elf64_Word
#define Elf_Sword Elf64_Sword
#define Elf_Xword Elf64_Xword
#define Elf_Sxword Elf64_Sxword
#define Elf_Addr Elf64_Addr
#define Elf_Off Elf64_Off
#define Elf_Section Elf64_Section
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym Elf64_Sym
#define Elf_Rel Elf64_Rel
#define Elf_Rela Elf64_Rela
#define Elf_Phdr Elf64_Phdr
#define Elf_Dyn Elf64_Dyn
#define Elf_Nhdr Elf64_Nhdr

#define ELF_ST_TYPE ELF64_ST_TYPE
#define ELF_ST_BIND ELF64_ST_BIND
#define ELF_ST_VISIBILITY ELF64_ST_VISIBILITY

#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM

#define DEC "%ld"
#define HEX "%.16lx"

#define SPACE	"        " // Used to align the view when printing 64 or 32 bit variables
#else
#error  "Unsupported arch"
#endif
/*** 32 - 64 BITS COMPAT ***/


/* MODES */
#define	HEADER	(1 << 0)
#define	SECTION	(1 << 1)
#define	PROGRAM	(1 << 2)
#define	SYMBOL	(1 << 3)
#define DYNAMIC (1 << 4)
#define RELOC	(1 << 5)
#define NOTES	(1 << 6)
#define ALL	(HEADER + SECTION + PROGRAM + SYMBOL + DYNAMIC + RELOC + NOTES)

/* PROTOTYPES */
void usage(const char *);
void banner();
int  elf_identification(int);
void elf_header(Elf_Ehdr);
void sht(char *);
void pht(char *);
void symbols(char *);
void dynamic(char *);
void relocations(char *);
void notes(char *);

int	numeric = 0;
int	shstrtab_offset = 0;

int main(int argc, char **argv)
{
	int		fd, opt, mode = 0;
	char		*elfptr;
	struct stat	statinfo;
	Elf_Ehdr	header;
	Elf_Shdr	shstrtab_section;

	if(argc < 3)
		usage(argv[0]);

	while((opt = getopt(argc, argv, "naHSPsDRhN")) != EOF)
		switch(opt){
				case 'n':
					numeric = 1;
					break;
				case 'a':
					mode |= ALL;
					break;
				case 'H':
					mode |= HEADER;
					break;
				case 'S':
					mode |= SECTION;
					break;
				case 'P':
					mode |= PROGRAM;
					break;
				case 's':
					mode |= SYMBOL;
					break;
				case 'D':
					mode |= DYNAMIC;
					break;
				case 'R':
					mode |= RELOC;
					break;
				case 'N':
					mode |= NOTES;
					break;
				case 'h':
				default:
					usage(argv[0]);
		}

	if(argv[optind] == NULL){
		fprintf(stderr, "Give me an ELF file\n");
		usage(argv[0]);
	}

	if((fd = open(argv[optind], O_RDONLY)) == -1){
		perror("open");
		exit(-1);
	}

	if(!elf_identification(fd)){
		fprintf(stderr, "This is not a supported ELF file\n");
		exit(-1);
	}

	if(fstat(fd, &statinfo) == -1){
		perror("stat");
		close(fd);
		exit(-1);
	}

	if((elfptr = (char *) mmap(NULL, statinfo.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED){
		perror("mmap");
		close(fd);
		exit(-1);
	}

	close(fd);

	header = *(Elf_Ehdr *) elfptr;
	shstrtab_section = *(Elf_Shdr *) (elfptr + header.e_shoff + header.e_shstrndx * sizeof(Elf_Shdr));
	if(shstrtab_section.sh_size > 0)
		shstrtab_offset  = shstrtab_section.sh_offset;

	if(mode & HEADER){
		printf("\n%sELF HEADER:%s\n", RED, RESET);
		elf_header(header);
	}

	if(mode & SECTION){
		printf("\n%sSECTION HEADER TABLE:%s\n", RED, RESET);
		if(header.e_shoff == 0)
			printf("[%sNO SECTION HEADER TABLE FOUND%s]\n", WHITE, RESET);
		else
			sht(elfptr);
	}

	if(mode & PROGRAM){
		printf("\n%sPROGRAM HEADER TABLE:%s\n", RED, RESET);
		pht(elfptr);
	}

	if(mode & SYMBOL){
		printf("\n%sSYMBOL TABLE:%s\n", RED, RESET);
		symbols(elfptr);
	}

	if(mode & DYNAMIC){
		printf("\n%sDYNAMIC INFORMATION:%s\n", RED, RESET);
		dynamic(elfptr);
	}

	if(mode & RELOC){
		printf("\n%sRELOCATIONS:%s\n", RED, RESET);
		relocations(elfptr);
	}

	if(mode & NOTES){
		printf("\n%sNOTES:%s\n", RED, RESET);
		notes(elfptr);
	}

	munmap(elfptr, statinfo.st_size);
	return 0;
}

void usage(const char *self)
{
	banner();

	fprintf(stderr, "Usage: %s [-n] <options> <elf_file>\n", self);
	fprintf(stderr, "\tOptions:\n");
	fprintf(stderr, "\t-n\tPrint everything in numeric values\n");
	fprintf(stderr, "\t-a\tAll(-HSPsdr)\n");
	fprintf(stderr, "\t-H\tELF header\n");
	fprintf(stderr, "\t-S\tSection headers\n");
	fprintf(stderr, "\t-P\tProgram headers\n");
	fprintf(stderr, "\t-s\tSymbol Table\n");
	fprintf(stderr, "\t-D\tDynamic information\n");
	fprintf(stderr, "\t-R\tRelocations\n");
	fprintf(stderr, "\t-N\tNotes\n");
	fprintf(stderr, "\t-h\tThis help\n");
	exit(0);
}

void banner()
{
	printf("%s######################################################%s\n", RED, RESET);
	printf("%s##%s%s         ELF ( x86 / x86_64 ) Dissector           %s%s##%s\n", RED, RESET, YELLOW, RESET, RED, RESET);
	printf("%s##%s%s                  by nitr0us                      %s%s##%s\n", RED, RESET, YELLOW, RESET, RED, RESET);
	printf("%s######################################################%s\n\n", RED, RESET);
}

int elf_identification(int fd)
{
	Elf_Ehdr	header;

	if(read(fd, &header, sizeof(header)) == -1){
		perror("elf_identification: read");
		return 0;
	}

	/* magic number verification */
	if(header.e_ident[EI_MAG0] != ELFMAG0 ||
			header.e_ident[EI_MAG1] != ELFMAG1 ||
			header.e_ident[EI_MAG2] != ELFMAG2 ||
			header.e_ident[EI_MAG3] != ELFMAG3){
		fprintf(stderr, "elf_identification: Invalid MAGIC Number\n");
		return 0;
	}

	return 1;
}

void elf_header(Elf_Ehdr hdr)
{
	int		k;

	printf("%se_ident:%s\t\t", WHITE, RESET);
	for(k = 0; k < EI_NIDENT; k++)
		printf("%.2x ", hdr.e_ident[k]);

	printf("\n%se_ident[EI_CLASS]:%s\t", WHITE, RESET);
	if(numeric)
		printf("0x%.2x", hdr.e_ident[EI_CLASS]);
	else
		switch(hdr.e_ident[EI_CLASS]){
			case ELFCLASSNONE:
				printf("ELFCLASSNONE");
				break;
			case ELFCLASS32:
				printf("ELFCLASS32");
				break;
			case ELFCLASS64:
				printf("ELFCLASS64");
				break;
			default:
				printf("%sINVALID CLASS%s (0x%x)", RED, RESET, hdr.e_ident[EI_CLASS]);
		}

	printf("\n%se_ident[EI_DATA]:%s\t", WHITE, RESET);
	if(numeric)
		printf("0x%.2x", hdr.e_ident[EI_DATA]);
	else
		switch(hdr.e_ident[EI_DATA]){
			case ELFDATANONE:
				printf("ELFDATANONE");
				break;
			case ELFDATA2LSB:
				printf("ELFDATA2LSB");
				break;
			case ELFDATA2MSB:
				printf("ELFDATA2MSB");
				break;
			default:
				printf("%sINVALID DATA%s (0x%x)", RED, RESET, hdr.e_ident[EI_DATA]);
		}

	printf("\n%se_ident[EI_VERSION]:%s\t", WHITE, RESET);
	if(numeric)
		printf("0x%.2x", hdr.e_ident[EI_VERSION]);
	else{
		if(hdr.e_ident[EI_VERSION] == EV_CURRENT)
			printf("EV_CURRENT");
		else
			printf("%sINVALID VERSION%s (0x%x)", RED, RESET, hdr.e_ident[EI_VERSION]);
	}

	printf("\n%se_ident[EI_OSABI]:%s\t", WHITE, RESET);
	if(numeric)
		printf("0x%.2x", hdr.e_ident[EI_OSABI]);
	else
		switch(hdr.e_ident[EI_OSABI]){
			case ELFOSABI_SYSV:
				printf("ELFOSABI_SYSV");
				break;
			case ELFOSABI_NETBSD:
				printf("ELFOSABI_NETBSD");
				break;
			case ELFOSABI_OPENBSD:
				printf("ELFOSABI_OPENBSD");
				break;
			case ELFOSABI_FREEBSD:
				printf("ELFOSABI_FREEBSD");
				break;
			case ELFOSABI_LINUX:
				printf("ELFOSABI_LINUX");
				break;
			case ELFOSABI_SOLARIS:
				printf("ELFOSABI_SOLARIS");
				break;
			default:
				printf("%s0x%x%s", RED, hdr.e_ident[EI_OSABI], RESET);
		}

	printf("\n%se_ident[EI_ABIVERSION]:%s\t0x%.2x", WHITE, RESET, hdr.e_ident[EI_ABIVERSION]);

	printf("\n%se_type:%s\t\t\t", WHITE, RESET);
	if(numeric)
		printf("0x%x", hdr.e_type);
	else
		switch(hdr.e_type){
			case ET_NONE:
				printf("ET_NONE");
				break;
			case ET_REL:
				printf("ET_REL");
				break;
			case ET_EXEC:
				printf("ET_EXEC");
				break;
			case ET_DYN:
				printf("ET_DYN");
				break;
			case ET_CORE:
				printf("ET_CORE");
				break;
			default:
				printf("%s0x%x%s", RED, hdr.e_type, RESET);
		}

	printf("\n%se_machine:%s\t\t", WHITE, RESET);
	if(numeric)
		printf("0x%x", hdr.e_machine);
	else
		switch(hdr.e_machine){
			case EM_NONE:
				printf("EM_NONE");
				break;
			case EM_SPARC:
				printf("EM_SPARC");
				break;
			case EM_386:
				printf("EM_386");
				break;
			case EM_MIPS:
				printf("EM_MIPS");
				break;
			case EM_PARISC:
				printf("EM_PARISC");
				break;
			case EM_PPC:
				printf("EM_PPC");
				break;
			case EM_SPARCV9:
				printf("EM_SPARCV9");
				break;
			case EM_X86_64:
				printf("EM_X86_649");
				break;
			default:
				printf("%s0x%x%s", RED, hdr.e_machine, RESET);
		}

	printf("\n%se_version:%s\t\t", WHITE, RESET);
	if(numeric)
		printf("0x%x", hdr.e_version);
	else
		switch(hdr.e_version){
			case EV_NONE:
				printf("EV_NONE");
				break;
			case EV_CURRENT:
				printf("EV_CURRENT");
				break;
			default:
				printf("%s0x%x%s", RED, hdr.e_version, RESET);
		}

	printf("\n%se_entry:%s\t\t0x"HEX, WHITE, RESET, hdr.e_entry);
	printf("\n%se_phoff:%s\t\t0x"HEX"\t("DEC")", WHITE, RESET, hdr.e_phoff, hdr.e_phoff);
	printf("\n%se_shoff:%s\t\t0x"HEX"\t("DEC")", WHITE, RESET, hdr.e_shoff, hdr.e_shoff);
	printf("\n%se_flags:%s\t\t0x%x\t(%d)", WHITE, RESET, hdr.e_flags, hdr.e_flags);
	printf("\n%se_ehsize:%s\t\t0x%x\t(%d)", WHITE, RESET, hdr.e_ehsize, hdr.e_ehsize);
	printf("\n%se_phentsize:%s\t\t0x%x\t(%d)", WHITE, RESET, hdr.e_phentsize, hdr.e_phentsize);
	printf("\n%se_phnum:%s\t\t0x%x\t(%d)", WHITE, RESET, hdr.e_phnum, hdr.e_phnum);
	printf("\n%se_shentsize:%s\t\t0x%x\t(%d)", WHITE, RESET, hdr.e_shentsize, hdr.e_shentsize);
	printf("\n%se_shnum:%s\t\t0x%x\t(%d)", WHITE, RESET, hdr.e_shnum, hdr.e_shnum);
	printf("\n%se_shstrndx:%s\t\t0x%x\t(%d)\n", WHITE, RESET, hdr.e_shstrndx, hdr.e_shstrndx);
}

void sht(char *mem)
{
	int		k;
	Elf_Ehdr	hdr = *(Elf_Ehdr *) mem;
	Elf_Shdr	*sections = (Elf_Shdr *) (mem + hdr.e_shoff);

	printf("%s[NR] sh_name              sh_type          sh_flags    sh_addr    sh_offset sh_size  sh_link sh_info sh_addralign sh_entsize%s\n", WHITE, RESET);

	for(k = 0; k < hdr.e_shnum; k++, sections++){
		printf("[%2d] ", k);

		if(numeric)
			printf("0x%-18.8x ", sections->sh_name);
		else{
			if(shstrtab_offset == 0)
				printf("0x%-15.8x ", sections->sh_name);
			else
				printf("%-20s ", mem + shstrtab_offset + sections->sh_name);
		}

		if(numeric)
			printf("0x%-12.8x ", sections->sh_type);
		else
			switch(sections->sh_type){
				case SHT_NULL:
					printf("%-14s ", "SHT_NULL");
					break;
				case SHT_PROGBITS:
					printf("%-14s ", "SHT_PROGBITS");
					break;
				case SHT_SYMTAB:
					printf("%-14s ", "SHT_SYMTAB");
					break;
				case SHT_STRTAB:
					printf("%-14s ", "SHT_STRTAB");
					break;
				case SHT_RELA:
					printf("%-14s ", "SHT_RELA");
					break;
				case SHT_HASH:
					printf("%-14s ", "SHT_HASH");
					break;
				case SHT_DYNAMIC:
					printf("%-14s ", "SHT_DYNAMIC");
					break;
				case SHT_NOTE:
					printf("%-14s ", "SHT_NOTE");
					break;
				case SHT_GNU_HASH:
					printf("%-14s ", "SHT_GNU_HASH");
					break;
				case SHT_NOBITS:
					printf("%-14s ", "SHT_NOBITS");
					break;
				case SHT_REL:
					printf("%-14s ", "SHT_REL");
					break;
				case SHT_SHLIB:
					printf("%-14s ", "SHT_SHLIB");
					break;
				case SHT_DYNSYM:
					printf("%-14s ", "SHT_DYNSYM");
					break;
				case SHT_INIT_ARRAY:
					printf("%-14s ", "SHT_INIT_ARRAY");
					break;
				case SHT_FINI_ARRAY:
					printf("%-14s ", "SHT_FINI_ARRAY");
					break;
				case SHT_GNU_verdef:
					printf("%-14s ", "SHT_VERDEF");
					break;
				case SHT_GNU_verneed:
					printf("%-14s ", "SHT_VERNEED");
					break;
				case SHT_GNU_versym:
					printf("%-14s ", "SHT_VERSYM");
					break;
				default:
					printf("%s0x%-12.8x%s ", RED, sections->sh_type, RESET);
			}

		if(numeric)
			printf("  0x%.8x  ", (unsigned int) sections->sh_flags);
		else
			printf("   %c %c %c      ", /* Needs to be improved. Seen more flags than only those three */
					(sections->sh_type & SHF_WRITE) ? 'W' : ' ',
					(sections->sh_type & SHF_ALLOC) ? 'A' : ' ',
					(sections->sh_type & SHF_EXECINSTR) ? 'X' : ' ');

		printf("0x%.8x ", (unsigned int) sections->sh_addr);
		printf("0x%.7x ", (unsigned int) sections->sh_offset);
		printf("0x%.6x   ", (unsigned int) sections->sh_size);
		printf("0x%.2x  ", sections->sh_link);
		printf("0x%.4x  ", sections->sh_info);
		printf("0x%.8x   ", (unsigned int) sections->sh_addralign);
		printf("0x%.4x\n", (unsigned int) sections->sh_entsize);
	}
}

void pht(char *mem)
{
	int		k;
	Elf_Ehdr	hdr = *(Elf_Ehdr *) mem;
	Elf_Phdr	*phdrs = (Elf_Phdr *) (mem + hdr.e_phoff);

	printf("%s[NR] p_type           p_offset    p_vaddr"SPACE"     p_paddr"SPACE"     p_filesz    p_memsz     p_flags  p_align%s\n", WHITE, RESET);

	for(k = 0; k < hdr.e_phnum; k++, phdrs++){
		printf("[%2d] ", k);

		if(numeric)
			printf("0x%-14.8x ", phdrs->p_type);
		else
			switch(phdrs->p_type){
				case PT_NULL:
					printf("%-17s", "PT_NULL");
					break;
				case PT_LOAD:
					printf("%-17s", "PT_LOAD");
					break;
				case PT_DYNAMIC:
					printf("%-17s", "PT_DYNAMIC");
					break;
				case PT_INTERP:
					printf("%-17s", "PT_INTERP");
					break;
				case PT_NOTE:
					printf("%-17s", "PT_NOTE");
					break;
				case PT_SHLIB:
					printf("%-17s", "PT_SHLIB");
					break;
				case PT_TLS:
					printf("%-17s", "PT_TLS");
					break;
				case PT_PHDR:
					printf("%-17s", "PT_PHDR");
					break;
				case PT_GNU_EH_FRAME:
					printf("%-17s", "PT_GNU_EH_FRAME");
					break;
				case PT_GNU_STACK:
					printf("%-17s", "PT_GNU_STACK");
					break;
				case PT_GNU_RELRO:
					printf("%-17s", "PT_GNU_RELRO");
					break;
				default:
					printf("%s0x%-14.8x%s ", RED, phdrs->p_type, RESET);
			}

		printf("0x%.8x  ", (unsigned int) phdrs->p_offset);
		printf("0x"HEX"  ", phdrs->p_vaddr);
		printf("0x"HEX"  ", phdrs->p_paddr);
		printf("0x%.8x  ", (unsigned int) phdrs->p_filesz);
		printf("0x%.8x  ", (unsigned int) phdrs->p_memsz);

		if(numeric)
			printf("0x%.4x   ", phdrs->p_flags);
		else
			printf(" %c %c %c   ",
					(phdrs->p_type & PF_X) ? 'X' : ' ',
					(phdrs->p_type & PF_W) ? 'W' : ' ',
					(phdrs->p_type & PF_R) ? 'R' : ' ');

		printf("0x%.8x\n", (unsigned int) phdrs->p_align);

		if(phdrs->p_type == PT_INTERP)
			printf("[Interpreter: %s%s%s]\n", WHITE, mem + phdrs->p_offset, RESET);
	}
}

void symbols(char *mem)
{
	int		k, l, flag = 0, strtab_off;
	Elf_Ehdr	hdr = *(Elf_Ehdr *) mem;
	Elf_Shdr	*shdr = (Elf_Shdr *) (mem + hdr.e_shoff), *shdr_table, stringtable;
	Elf_Sym		*sym;

	shdr_table = shdr;

	for(k = 0; k < hdr.e_shnum; k++, shdr++){
		if(shdr->sh_type != SHT_SYMTAB && shdr->sh_type != SHT_DYNSYM)
			continue;

		flag = 1;

		printf("Found symbol table [%s%s%s] with %s"DEC"%s entries:\n", YELLOW, mem + shstrtab_offset + shdr->sh_name, RESET, YELLOW, shdr->sh_size / shdr->sh_entsize, RESET);

		sym = (Elf_Sym *) (mem + shdr->sh_offset);
		stringtable = *(Elf_Shdr *) (mem + hdr.e_shoff + (shdr->sh_link * sizeof(Elf_Shdr)));
		strtab_off  = stringtable.sh_offset;

		printf("%s[ NR ] st_value"SPACE"   st_size     TYPE        BINDING    VISIBILITY     st_shndx    st_name%s\n", WHITE, RESET);

		for(l = 0; l < shdr->sh_size / shdr->sh_entsize; l++, sym++){
			printf("[%4d] ", l);

			printf("0x"HEX" ", sym->st_value);
			printf("0x%.5x  ", (unsigned int) sym->st_size);

			if(numeric)
				printf("   0x%.2x ", sym->st_info);
			else
				switch(ELF_ST_TYPE(sym->st_info)){
					case STT_NOTYPE:
						printf("%-12s  ", "STT_NOTYPE");
						break;
					case STT_OBJECT:
						printf("%-12s  ", "STT_OBJECT");
						break;
					case STT_FUNC:
						printf("%-12s  ", "STT_FUNC");
						break;
					case STT_SECTION:
						printf("%-12s  ", "STT_SECTION");
						break;
					case STT_FILE:
						printf("%-12s  ", "STT_FILE");
						break;
					case STT_COMMON:
						printf("%-12s  ", "STT_COMMON");
						break;
					case STT_TLS:
						printf("%-12s  ", "STT_TLS");
						break;
					case STT_NUM:
						printf("%-12s  ", "STT_NUM");
						break;
					default:
						printf("   %s0x%.2x%s       ", RED, sym->st_info, RESET);
				}

			if(numeric)
				printf("        0x%.2x ", sym->st_info);
			else
				switch(ELF_ST_BIND(sym->st_info)){
					case STB_LOCAL:
						printf("%-11s ", "STB_LOCAL");
						break;
					case STB_GLOBAL:
						printf("%-11s ", "STB_GLOBAL");
						break;
					case STB_WEAK:
						printf("%-11s ", "STB_WEAK");
						break;
					case STB_NUM:
						printf("%-11s ", "STB_NUM");
						break;
					default:
						printf("  %s0x%.2x%s       ", RED, sym->st_info, RESET);
				}

			if(numeric)
				printf("        0x%.2x        ", sym->st_other);
			else
				switch(ELF_ST_VISIBILITY(sym->st_other)){
					case STV_DEFAULT:
						printf("%-14s ", "STV_DEFAULT");
						break;
					case STV_INTERNAL:
						printf("%-14s ", "STV_INTERNAL");
						break;
					case STV_HIDDEN:
						printf("%-14s ", "STV_HIDDEN");
						break;
					case STV_PROTECTED:
						printf("%-14s ", "STV_PROTECTED");
						break;
					default:
						printf("   %s0x%.2x%s        ", RED, sym->st_other, RESET);	
				}

			if(numeric)
				printf(" 0x%.4x     ", sym->st_shndx);
			else
				switch(sym->st_shndx){
					case SHN_UNDEF:
						printf("%-11s ", "SHN_UNDEF");
						break;
					case SHN_ABS:
						printf("%-11s ", "SHN_ABS");
						break;
					case SHN_COMMON:
						printf("%-11s ", "SHN_COMMON");
						break;
					default:
						printf("  0x%.2x      ", sym->st_shndx);
				}

			if(numeric)
				printf("0x%.4x\n", sym->st_name);
			else{
				if(ELF_ST_TYPE(sym->st_info) == STT_SECTION)
					printf("%s\n", mem + shstrtab_offset + shdr_table[sym->st_shndx].sh_name);
				else
					printf("%s\n", mem + strtab_off + sym->st_name);
			}
		}

		putchar('\n');
	}

	if(!flag)
		printf("[%sNO SYMBOL TABLE FOUND%s]\n", WHITE, RESET);
}

void dynamic(char *mem)
{
	int		k, l, flag = 0, strtab_offset;
	Elf_Ehdr	hdr = *(Elf_Ehdr *) mem;
	Elf_Shdr	*shdr = (Elf_Shdr *) (mem + hdr.e_shoff), stringtable;
	Elf_Dyn		*dyn;

	for(k = 0; k < hdr.e_shnum; k++, shdr++){
		if(shdr->sh_type != SHT_DYNAMIC)
			continue;

		flag = 1;

		printf("Found Dynamic Section [%s%s%s] with %s"DEC"%s entries:\n", YELLOW, mem + shstrtab_offset + shdr->sh_name, RESET, YELLOW, shdr->sh_size / shdr->sh_entsize, RESET);

		dyn = (Elf_Dyn *) (mem + shdr->sh_offset);
		stringtable = *(Elf_Shdr *) (mem + hdr.e_shoff + (shdr->sh_link * sizeof(Elf_Shdr)));
		strtab_offset  = stringtable.sh_offset;

		printf("%s[ NR ]  d_tag"SPACE"       TYPE                 NAME/VALUE%s\n", WHITE, RESET);

		for(l = 0; l < shdr->sh_size / shdr->sh_entsize; l++, dyn++){
			printf("[%4d]  ", l);

			printf("0x"HEX"  ", dyn->d_tag);

			if(numeric)
				printf("0x%.8x           ", (unsigned int) dyn->d_tag);
			else
				switch(dyn->d_tag){
					case DT_NULL:
						printf("%-20s ", "DT_NULL");
						break;
					case DT_NEEDED:
						printf("%-20s ", "DT_NEEDED");
						break;
					case DT_PLTRELSZ:
						printf("%-20s ", "DT_PLTRELSZ");
						break;
					case DT_PLTGOT:
						printf("%-20s ", "DT_PLTGOT");
						break;
					case DT_HASH:
						printf("%-20s ", "DT_HASH");
						break;
					case DT_GNU_HASH:
						printf("%-20s ", "DT_GNU_HASH");
						break;
					case DT_STRTAB:
						printf("%-20s ", "DT_STRTAB");
						break;
					case DT_SYMTAB:
						printf("%-20s ", "DT_SYMTAB");
						break;
					case DT_STRSZ:
						printf("%-20s ", "DT_STRSZ");
						break;
					case DT_SYMENT:
						printf("%-20s ", "DT_SYMENT");
						break;
					case DT_INIT:
						printf("%-20s ", "DT_INIT");
						break;
					case DT_FINI:
						printf("%-20s ", "DT_FINI");
						break;
					case DT_SONAME:
						printf("%-20s ", "DT_SONAME");
						break;
					case DT_RPATH:
						printf("%-20s ", "DT_RPATH");
						break;
					case DT_SYMBOLIC:
						printf("%-20s ", "DT_SYMBOLIC");
						break;
					case DT_REL:
						printf("%-20s ", "DT_REL");
						break;
					case DT_RELSZ:
						printf("%-20s ", "DT_RELSZ");
						break;
					case DT_RELENT:
						printf("%-20s ", "DT_RELENT");
						break;
					case DT_PLTREL:
						printf("%-20s ", "DT_PLTREL");
						break;
					case DT_DEBUG:
						printf("%-20s ", "DT_DEBUG");
						break;
					case DT_TEXTREL:
						printf("%-20s ", "DT_TEXTREL");
						break;
					case DT_JMPREL:
						printf("%-20s ", "DT_JMPREL");
						break;
					case DT_BIND_NOW:
						printf("%-20s ", "DT_BIND_NOW");
						break;
					case DT_INIT_ARRAY:
						printf("%-20s ", "DT_INIT_ARRAY");
						break;
					case DT_FINI_ARRAY:
						printf("%-20s ", "DT_FINI_ARRAY");
						break;
					case DT_INIT_ARRAYSZ:
						printf("%-20s ", "DT_INIT_ARRAYSZ");
						break;
					case DT_FINI_ARRAYSZ:
						printf("%-20s ", "DT_FINI_ARRAYSZ");
						break;
					case DT_VERSYM:
						printf("%-20s ", "DT_VERSYM");
						break;
					case DT_RELCOUNT:
						printf("%-20s ", "DT_RELCOUNT");
						break;
					case DT_VERDEF:
						printf("%-20s ", "DT_VERDEF");
						break;
					case DT_VERDEFNUM:
						printf("%-20s ", "DT_VERDEFNUM");
						break;
					case DT_VERNEED:
						printf("%-20s ", "DT_VERNEED");
						break;
					case DT_VERNEEDNUM:
						printf("%-20s ", "DT_VERNEEDNUM");
						break;
					default:
						printf("%s0x%.8x%s           ", RED, (unsigned int) dyn->d_tag, RESET);
				}

			switch(dyn->d_tag){
				case DT_NEEDED:
				case DT_SONAME:
				case DT_RPATH:
					printf("%s\n", mem + strtab_offset + dyn->d_un.d_val);
					break;
				case DT_PLTGOT:
				case DT_HASH:
				case DT_STRTAB:
				case DT_SYMTAB:
				case DT_INIT:
				case DT_FINI:
				case DT_INIT_ARRAY:
				case DT_FINI_ARRAY:
				case DT_REL:
				case DT_JMPREL:
				case DT_VERSYM:
				case DT_VERNEED:
				case DT_GNU_HASH:
					printf("0x"HEX"\n", dyn->d_un.d_ptr);
					break;
				case DT_PLTRELSZ:
				case DT_STRSZ:
				case DT_SYMENT:
				case DT_RELSZ:
				case DT_RELENT:
				case DT_INIT_ARRAYSZ:
				case DT_FINI_ARRAYSZ:
					printf(HEX" bytes\n", dyn->d_un.d_val);
					break;
				case DT_PLTREL:
					printf("%s\n", (dyn->d_un.d_val == DT_REL) ? "DT_REL" : "DT_RELA");
					break;
				case DT_VERNEEDNUM:
				case DT_DEBUG:
					printf("0x"HEX"\n", dyn->d_un.d_val);
					break;
				default:
					putchar('\n');
			}

			if(dyn->d_tag == DT_NULL)	/* End of _DYNAMIC[] */
				break;
		}

	}

	if(!flag)
		printf("[%sNO DYNAMIC SECTION FOUND%s]\n", WHITE, RESET);
}

void relocations(char *mem)
{
	int		k, l, symndx = 0, flag = 0, symstrtab_offset;
	Elf_Ehdr	hdr = *(Elf_Ehdr *) mem;
	Elf_Shdr	*shdr = (Elf_Shdr *) (mem + hdr.e_shoff), *shdr_table, symtab_section, stringtable;
	Elf_Sym		*sym;
	Elf_Rel		*rel;
	Elf_Rela	*rela;

	shdr_table = shdr;

	for(k = 0; k < hdr.e_shnum; k++, shdr++){
		if(shdr->sh_type != SHT_REL && shdr->sh_type != SHT_RELA)
			continue;

		flag = 1;

		printf("Found Relocation Section [%s%s%s] with %s"DEC" %s%s entries:\n", YELLOW, mem + shstrtab_offset + shdr->sh_name, RESET, YELLOW, shdr->sh_size / shdr->sh_entsize, shdr->sh_type == SHT_REL ? "SHT_REL" : "SHT_RELA", RESET);

		if(shdr->sh_type == SHT_REL)
			rel =  (Elf_Rel *)  (mem + shdr->sh_offset);
		else
			rela = (Elf_Rela *) (mem + shdr->sh_offset);

		symtab_section = shdr_table[shdr->sh_link];
		stringtable = *(Elf_Shdr *) (mem + hdr.e_shoff + (symtab_section.sh_link * sizeof(Elf_Shdr)));
		symstrtab_offset  = stringtable.sh_offset;
		sym = (Elf_Sym *) (mem + symtab_section.sh_offset);

		printf("%s[ NR ] r_offset"SPACE"   r_info      TYPE             SYM[ndx]  SYMBOL NAME + r_addend%s\n", WHITE, RESET);

		for(l = 0; l < shdr->sh_size / shdr->sh_entsize; l++){
			printf("[%4d] ", l);

			printf("0x"HEX" ", shdr->sh_type == SHT_REL ? rel->r_offset : rela->r_offset);
			printf("0x%.8x  ", shdr->sh_type == SHT_REL ? (unsigned int) rel->r_info : (unsigned int) rela->r_info);

			if(numeric)
				printf("0x%.8x     ", shdr->sh_type == SHT_REL ? (unsigned int) rel->r_info : (unsigned int) rela->r_info);
			else
				switch(ELF_R_TYPE(shdr->sh_type == SHT_REL ? rel->r_info : rela->r_info)){
					case R_386_NONE:
						printf("%-14s ", "R_386_NONE");
						break;
					case R_386_32:
						printf("%-14s ", "R_386_32");
						break;
					case R_386_PC32:
						printf("%-14s ", "R_386_PC32");
						break;
					case R_386_GOT32:
						printf("%-14s ", "R_386_GOT32");
						break;
					case R_386_PLT32:
						printf("%-14s ", "R_386_PLT32");
						break;
					case R_386_COPY:
						printf("%-14s ", "R_386_COPY");
						break;
					case R_386_GLOB_DAT:
						printf("%-14s ", "R_386_GLOB_DAT");
						break;
					case R_386_JMP_SLOT:
						printf("%-14s ", "R_386_JMP_SLOT");
						break;
					case R_386_RELATIVE:
						printf("%-14s ", "R_386_RELATIVE");
						break;
					case R_386_GOTOFF:
						printf("%-14s ", "R_386_GOTOFF");
						break;
					case R_386_GOTPC:
						printf("%-14s ", "R_386_GOTPC");
						break;
					default:
						printf("%s0x%.8x%s     ", RED, shdr->sh_type == SHT_REL ? (unsigned int) rel->r_info : (unsigned int) rela->r_info, RESET);
				}

			symndx = ELF_R_SYM(shdr->sh_type == SHT_REL ? rel->r_info : rela->r_info);
			printf("    %.4d    ", symndx);

			if(ELF_ST_TYPE(sym[symndx].st_info) == STT_SECTION)
				printf("%s", mem + shstrtab_offset + shdr_table[sym[symndx].st_shndx].sh_name);
			else
				printf("%s", mem + symstrtab_offset + sym[symndx].st_name);

			if(shdr->sh_type == SHT_REL){
				putchar('\n');
				rel++;
			} else {
				printf(" + 0x%x\n", (unsigned int) rela->r_addend);
				rela++;
			}
		}

		putchar('\n');
	}

	if(!flag)
		printf("[%sNO RELOCATIONS FOUND%s]\n", WHITE, RESET);
}

/* 
 * It doesn't loop through the notes.
 * It just parses the 1st entry found in every SHT_NOTE section found.
 */
void notes(char *mem)
{
	int		k, l, flag = 0, *abi;
	Elf_Ehdr	hdr = *(Elf_Ehdr *) mem;
	Elf_Shdr	*shdr = (Elf_Shdr *) (mem + hdr.e_shoff);
	Elf_Nhdr	*note;
	char		*note_name;

	for(k = 0; k < hdr.e_shnum; k++, shdr++){
		if(shdr->sh_type != SHT_NOTE)
			continue;

		flag = 1;

		printf("Found Note Section [%s%s%s] with %s"DEC"%s bytes:\n", YELLOW, mem + shstrtab_offset + shdr->sh_name, RESET, YELLOW, shdr->sh_size, RESET);

		note = (Elf_Nhdr *) (mem + shdr->sh_offset);

		printf("%s[ NR ] n_namesz      n_descsz      n_type%s\n", WHITE, RESET);

		printf("[%4d] ", 0);

		printf("0x%.8x    ", note->n_namesz);
		printf("0x%.8x    ", note->n_descsz);

		if(numeric)
			printf("0x%.8x\n", note->n_type);

		switch(note->n_type){
			case NT_GNU_ABI_TAG:
				note_name = (char *) (void *) note + sizeof(*note);
				printf("%s", numeric ? "" : strcmp(note_name, ELF_NOTE_GNU) == 0 ? "NT_GNU_ABI_TAG\n" : "NT_VERSION\n");

				printf("\tName:\t%s\n", note_name);

				if(strcmp(note_name, ELF_NOTE_GNU))
					break;

				abi = (int *) ((void *) note + sizeof(*note) + note->n_namesz);

				putchar('\t');

				if(numeric){
					printf("OS:\t0x%.8x\n", *(abi++));
					printf("\tABI:\tMajor: 0x%.8x   ",  *(abi++));
					printf("Minor: 0x%.8x   ",  *(abi++));
					printf("Subminor: 0x%.8x\n", *(abi));
				} else {
					switch(*abi){
						case ELF_NOTE_OS_LINUX:
							printf("OS:\tELF_NOTE_OS_LINUX\n");
							break;
						case ELF_NOTE_OS_GNU:
							printf("OS:\tELF_NOTE_OS_GNU\n");
							break;
						case ELF_NOTE_OS_SOLARIS2:
							printf("OS:\tELF_NOTE_OS_SOLARIS2\n");
							break;
						case ELF_NOTE_OS_FREEBSD:
							printf("OS:\tELF_NOTE_OS_FREEBSD\n");
							break;
						default:
							printf("OS:\t%s0x%.8x%s\n", RED, *abi, RESET);
					}

					printf("\tABI:\t%d.", *(++abi));
					printf("%d.", *(++abi));
					printf("%d\n",*(++abi));
				}
				break;
			case NT_GNU_HWCAP:
				printf("%s", numeric ? "" : "NT_GNU_HWCAP\n");
				break;
			case NT_GNU_BUILD_ID:
				printf("%s", numeric ? "" : "NT_GNU_BUILD_ID\n");
				printf("\tName:\t%s\n", (char *) ((void *) note + sizeof(*note)));

				printf("\tBuildID: ");

				char *desc = (char *) (void *) note + sizeof(*note) + note->n_namesz;

				for(l = 0; l < note->n_descsz; l++)
					printf("%.2x", (*(desc++) & 0xff));

				putchar('\n');

				break;
			case NT_GNU_GOLD_VERSION:
				printf("%s", numeric ? "" : "NT_GNU_GOLD_VERSION\n");
				break;
			default:
				printf("%s0x%.8x%s\n", RED, note->n_type, RESET);
		}

		putchar('\n');
	}

	if(!flag)
		printf("[%sNO NOTES FOUND%s]\n", WHITE, RESET);
}
