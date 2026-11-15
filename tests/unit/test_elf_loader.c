/**
 * @file test_elf_loader.c
 * @brief Unit tests for the ELF64 binary loader using a synthetic .ko binary.
 */
#include "loader/elf_loader.h"
#include "loader/binary_image.h"
#include "platform/logging.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* ── ELF constants ───────────────────────────────────────────────────────── */
#define ELFMAG0 0x7F
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFCLASS64  2
#define ELFDATA2LSB 1
#define ELFCLASS32  1
#define ET_REL      1
#define EM_X86_64   62
#define SHT_NULL     0
#define SHT_PROGBITS 1
#define SHT_SYMTAB   2
#define SHT_STRTAB   3
#define SHT_RELA     4
#define SHF_ALLOC      0x2
#define SHF_EXECINSTR  0x4
#define SHF_WRITE      0x1
#define STB_GLOBAL  1
#define STT_FUNC    2
#define STT_NOTYPE  0
#define SHN_UNDEF   0
#define R_X86_64_PLT32 4
#define ELF_ST_INFO(b,t) (uint8_t)(((b)<<4)|((t)&0xF))

#pragma pack(push,1)
typedef struct {
    uint8_t ident[16]; uint16_t type,machine; uint32_t version;
    uint64_t entry,phoff,shoff; uint32_t flags;
    uint16_t ehsz,phesz,phnum,shesz,shnum,shstrndx;
} t_ehdr;
typedef struct {
    uint32_t name,type; uint64_t flags,addr,offset,size;
    uint32_t link,info; uint64_t align,entsize;
} t_shdr;
typedef struct {
    uint32_t name; uint8_t info,other; uint16_t shndx; uint64_t value,size;
} t_sym;
typedef struct { uint64_t offset,info; int64_t addend; } t_rela;
#pragma pack(pop)

/* Layout of our synthetic .ko:
 *  0x000  ELF header (64 bytes)
 *  0x040  .text   (32 bytes NOP)
 *  0x060  .data   (16 bytes zero)
 *  0x070  .modinfo (key=value pairs)
 *  0x0C0  .strtab  (symbol names)
 *  0x100  .shstrtab (section names)
 *  0x140  .symtab  (5 entries)
 *  0x200  .rela.text (2 entries)
 *  0x280  section headers (8 x 64 = 0x200)
 *  total: 0x480
 */
#define BUFSZ     0x800
#define TEXT_OFF  0x040
#define TEXT_SZ   0x020
#define DATA_OFF  0x060
#define DATA_SZ   0x010
#define MI_OFF    0x070
#define MI_SZ     0x050
#define STR_OFF   0x0C0
#define STR_SZ    0x040
#define SHS_OFF   0x100
#define SHS_SZ    0x040
#define SYM_OFF   0x140
#define SYM_SZ    (5*sizeof(t_sym))
#define REL_OFF   0x200
#define REL_SZ    (2*sizeof(t_rela))
#define SHD_OFF   0x280
#define NSHDRS    8

static uint8_t g_buf[BUFSZ];
static char    g_tmp[256];
static void    cleanup(void){ if(g_tmp[0]) unlink(g_tmp); }

static uint32_t sapp(uint8_t *tb, uint32_t *pos, uint32_t max, const char *s) {
    uint32_t off=*pos; size_t l=strlen(s)+1;
    if(*pos+l>max) return 0;
    memcpy(tb+off,s,l); *pos+=(uint32_t)l; return off;
}

static void build_elf(void) {
    memset(g_buf,0,BUFSZ);

    /* .text: NOP sled */
    memset(g_buf+TEXT_OFF,0x90,TEXT_SZ);

    /* .modinfo */
    uint8_t *mi=g_buf+MI_OFF; uint32_t mp=0;
    const char *vm="vermagic=6.6.0-generic SMP preempt mod_unload";
    memcpy(mi+mp,vm,strlen(vm)+1); mp+=(uint32_t)strlen(vm)+1;
    const char *lic="license=GPL";
    memcpy(mi+mp,lic,strlen(lic)+1); mp+=(uint32_t)strlen(lic)+1;
    const char *aut="author=CBAE Test";
    memcpy(mi+mp,aut,strlen(aut)+1);

    /* .strtab */
    uint8_t *strtab=g_buf+STR_OFF; uint32_t spos=0;
    strtab[spos++]='\0';
    uint32_t n_init =sapp(strtab,&spos,STR_SZ,"test_module_init");
    uint32_t n_exit =sapp(strtab,&spos,STR_SZ,"test_module_exit");
    uint32_t n_irq  =sapp(strtab,&spos,STR_SZ,"request_irq");
    uint32_t n_km   =sapp(strtab,&spos,STR_SZ,"kmalloc");

    /* .shstrtab */
    uint8_t *shst=g_buf+SHS_OFF; uint32_t hp=0;
    shst[hp++]='\0';
    uint32_t h_text   =sapp(shst,&hp,SHS_SZ,".text");
    uint32_t h_data   =sapp(shst,&hp,SHS_SZ,".data");
    uint32_t h_symtab =sapp(shst,&hp,SHS_SZ,".symtab");
    uint32_t h_strtab =sapp(shst,&hp,SHS_SZ,".strtab");
    uint32_t h_rela   =sapp(shst,&hp,SHS_SZ,".rela.text");
    uint32_t h_mi     =sapp(shst,&hp,SHS_SZ,".modinfo");
    uint32_t h_shst   =sapp(shst,&hp,SHS_SZ,".shstrtab");

    /* .symtab: 5 symbols */
    t_sym *syms=(t_sym*)(g_buf+SYM_OFF);
    memset(syms,0,SYM_SZ);
    /* [0] null */
    /* [1] test_module_init: global func, defined in .text (shndx=1) */
    syms[1].name=n_init; syms[1].info=ELF_ST_INFO(STB_GLOBAL,STT_FUNC);
    syms[1].shndx=1; syms[1].value=0; syms[1].size=16;
    /* [2] test_module_exit: global func, defined in .text */
    syms[2].name=n_exit; syms[2].info=ELF_ST_INFO(STB_GLOBAL,STT_FUNC);
    syms[2].shndx=1; syms[2].value=16; syms[2].size=8;
    /* [3] request_irq: undefined (kernel import) */
    syms[3].name=n_irq; syms[3].info=ELF_ST_INFO(STB_GLOBAL,STT_NOTYPE);
    syms[3].shndx=SHN_UNDEF;
    /* [4] kmalloc: undefined (kernel import) */
    syms[4].name=n_km; syms[4].info=ELF_ST_INFO(STB_GLOBAL,STT_NOTYPE);
    syms[4].shndx=SHN_UNDEF;

    /* .rela.text: 2 relocations */
    t_rela *rels=(t_rela*)(g_buf+REL_OFF);
    rels[0].offset=0x04; rels[0].info=((uint64_t)3<<32)|R_X86_64_PLT32; rels[0].addend=-4;
    rels[1].offset=0x10; rels[1].info=((uint64_t)4<<32)|R_X86_64_PLT32; rels[1].addend=-4;

    /* Section headers */
    t_shdr *sh=(t_shdr*)(g_buf+SHD_OFF);
    /* [0] NULL */
    /* [1] .text */
    sh[1].name=h_text; sh[1].type=SHT_PROGBITS;
    sh[1].flags=SHF_ALLOC|SHF_EXECINSTR;
    sh[1].offset=TEXT_OFF; sh[1].size=TEXT_SZ; sh[1].align=16;
    /* [2] .data */
    sh[2].name=h_data; sh[2].type=SHT_PROGBITS;
    sh[2].flags=SHF_ALLOC|SHF_WRITE;
    sh[2].offset=DATA_OFF; sh[2].size=DATA_SZ; sh[2].align=8;
    /* [3] .symtab: link=4(.strtab), info=3(first global) */
    sh[3].name=h_symtab; sh[3].type=SHT_SYMTAB;
    sh[3].offset=SYM_OFF; sh[3].size=SYM_SZ;
    sh[3].link=4; sh[3].info=3; sh[3].align=8; sh[3].entsize=sizeof(t_sym);
    /* [4] .strtab */
    sh[4].name=h_strtab; sh[4].type=SHT_STRTAB;
    sh[4].offset=STR_OFF; sh[4].size=STR_SZ; sh[4].align=1;
    /* [5] .rela.text: link=3(.symtab), info=1(.text target) */
    sh[5].name=h_rela; sh[5].type=SHT_RELA;
    sh[5].offset=REL_OFF; sh[5].size=REL_SZ;
    sh[5].link=3; sh[5].info=1; sh[5].align=8; sh[5].entsize=sizeof(t_rela);
    /* [6] .modinfo */
    sh[6].name=h_mi; sh[6].type=SHT_PROGBITS;
    sh[6].offset=MI_OFF; sh[6].size=MI_SZ; sh[6].align=1;
    /* [7] .shstrtab */
    sh[7].name=h_shst; sh[7].type=SHT_STRTAB;
    sh[7].offset=SHS_OFF; sh[7].size=SHS_SZ; sh[7].align=1;

    /* ELF header */
    t_ehdr *hdr=(t_ehdr*)g_buf;
    hdr->ident[0]=ELFMAG0; hdr->ident[1]=ELFMAG1;
    hdr->ident[2]=ELFMAG2; hdr->ident[3]=ELFMAG3;
    hdr->ident[4]=ELFCLASS64; hdr->ident[5]=ELFDATA2LSB; hdr->ident[6]=1;
    hdr->type=ET_REL; hdr->machine=EM_X86_64; hdr->version=1;
    hdr->shoff=SHD_OFF; hdr->ehsz=sizeof(t_ehdr);
    hdr->shesz=sizeof(t_shdr); hdr->shnum=NSHDRS; hdr->shstrndx=7;
}

static void write_elf(void) {
    build_elf();
    snprintf(g_tmp,sizeof(g_tmp),"/tmp/cbae_elf_test_%d.ko",(int)getpid());
    atexit(cleanup);
    FILE *f=fopen(g_tmp,"wb"); assert(f);
    fwrite(g_buf,1,BUFSZ,f); fclose(f);
}

/* ── Tests ───────────────────────────────────────────────────────────────── */
static void t_valid_load(void) {
    cbae_binary_image_t *img=NULL;
    assert(cbae_elf_load(g_tmp,&img)==CBAE_OK);
    assert(img && img->format==CBAE_FMT_ELF64);
    assert(img->arch==CBAE_ARCH_X86_64);
    assert(img->os_origin==CBAE_OS_LINUX);
    assert(img->load_base==0);
    cbae_image_destroy(&img); assert(!img);
    printf("  [PASS] valid ELF64 load\n");
}

static void t_sections(void) {
    cbae_binary_image_t *img=NULL;
    cbae_elf_load(g_tmp,&img); assert(img);
    /* 8 shdrs, NULL skipped => 7 sections */
    assert(img->section_count==7);
    cbae_section_t *tx=cbae_image_section_by_name(img,".text");
    assert(tx && cbae_section_is_code(tx));
    cbae_section_t *da=cbae_image_section_by_name(img,".data");
    assert(da && (da->flags&CBAE_SEC_WRITE) && !(da->flags&CBAE_SEC_EXEC));
    cbae_image_destroy(&img);
    printf("  [PASS] sections (count=7, .text exec, .data writable)\n");
}

static void t_va_to_ptr(void) {
    cbae_binary_image_t *img=NULL;
    cbae_elf_load(g_tmp,&img); assert(img);
    /* .text is section index 1 => synthetic VA = 1*0x400000 */
    cbae_addr_t va=0x400000ULL;
    const uint8_t *p=cbae_image_va_to_ptr(img,va);
    assert(p && *p==0x90);
    assert(!cbae_image_va_to_ptr(img,va+TEXT_SZ+1));
    cbae_image_destroy(&img);
    printf("  [PASS] VA-to-ptr (.text NOP, past-end=NULL)\n");
}

static void t_symbols(void) {
    cbae_binary_image_t *img=NULL;
    cbae_elf_load(g_tmp,&img); assert(img);
    /* null sym skipped + 4 real => 4 */
    assert(img->symbol_count==4);
    cbae_symbol_t *init=cbae_image_symbol_by_name(img,"test_module_init");
    assert(init && init->kind==CBAE_KIND_FUNCTION && init->binding==CBAE_BIND_GLOBAL);
    assert(init->type==CBAE_SYM_EXPORT);
    cbae_image_destroy(&img);
    printf("  [PASS] symbols (count=4, test_module_init is global func)\n");
}

static void t_imports(void) {
    cbae_binary_image_t *img=NULL;
    cbae_elf_load(g_tmp,&img); assert(img);
    /* 2 RELA entries both SHN_UNDEF => 2 imports */
    assert(img->import_count==2);
    cbae_import_entry_t *irq=cbae_image_import_by_name(img,"request_irq");
    assert(irq && !strcmp(irq->module,"kernel"));
    assert(irq->state==CBAE_IMPORT_UNRESOLVED);
    assert(!cbae_import_has_iat(irq));
    assert(cbae_import_has_rela(irq));
    cbae_import_entry_t *km=cbae_image_import_by_name(img,"kmalloc");
    assert(km && km->rela_type==R_X86_64_PLT32);
    cbae_image_destroy(&img);
    printf("  [PASS] imports (count=2: request_irq, kmalloc)\n");
}

static void t_modinfo(void) {
    cbae_binary_image_t *img=NULL;
    cbae_elf_load(g_tmp,&img); assert(img);
    assert(strstr(img->meta.elf.kernel_version,"6.6.0")!=NULL);
    assert(!strcmp(img->meta.elf.module_license,"GPL"));
    cbae_image_destroy(&img);
    printf("  [PASS] .modinfo (vermagic has 6.6.0, license=GPL)\n");
}

static void t_relocs(void) {
    cbae_binary_image_t *img=NULL;
    cbae_elf_load(g_tmp,&img); assert(img);
    assert(img->reloc_count==2);
    for(uint32_t i=0;i<img->reloc_count;i++) {
        assert(img->relocations[i].type==CBAE_RELOC_PLT32);
        assert(img->relocations[i].references_import==true);
    }
    cbae_image_destroy(&img);
    printf("  [PASS] relocs (count=2, PLT32, refs_import=true)\n");
}

static void t_bad_magic(void) {
    char p[256]; snprintf(p,sizeof(p),"/tmp/cbae_badelf_%d.ko",(int)getpid());
    FILE *f=fopen(p,"wb"); uint8_t junk[128]; memset(junk,0xCC,sizeof(junk));
    fwrite(junk,1,sizeof(junk),f); fclose(f);
    cbae_binary_image_t *img=NULL;
    assert(cbae_elf_load(p,&img)==CBAE_ERR_PARSE); assert(!img);
    unlink(p);
    printf("  [PASS] bad ELF magic -> CBAE_ERR_PARSE\n");
}

static void t_32bit_rejected(void) {
    char p[256]; snprintf(p,sizeof(p),"/tmp/cbae_elf32_%d.ko",(int)getpid());
    uint8_t buf[64]; memset(buf,0,sizeof(buf));
    buf[0]=ELFMAG0; buf[1]=ELFMAG1; buf[2]=ELFMAG2; buf[3]=ELFMAG3;
    buf[4]=ELFCLASS32; buf[5]=ELFDATA2LSB;
    FILE *f=fopen(p,"wb"); fwrite(buf,1,sizeof(buf),f); fclose(f);
    cbae_binary_image_t *img=NULL;
    assert(cbae_elf_load(p,&img)==CBAE_ERR_PARSE); assert(!img);
    unlink(p);
    printf("  [PASS] ELFCLASS32 -> CBAE_ERR_PARSE\n");
}

static void t_empty_file(void) {
    char p[256]; snprintf(p,sizeof(p),"/tmp/cbae_emptyelf_%d.ko",(int)getpid());
    FILE *f=fopen(p,"wb"); fclose(f);
    cbae_binary_image_t *img=NULL;
    cbae_err_t e=cbae_elf_load(p,&img);
    assert(e==CBAE_ERR_PARSE||e==CBAE_ERR_IO); assert(!img);
    unlink(p);
    printf("  [PASS] empty file -> CBAE_ERR_PARSE/IO\n");
}

static void t_section_at_va(void) {
    cbae_binary_image_t *img=NULL;
    cbae_elf_load(g_tmp,&img); assert(img);
    cbae_section_t *s=cbae_image_section_at_va(img,0x400000ULL+4);
    assert(s && !strcmp(s->name,".text"));
    assert(!cbae_image_section_at_va(img,0x1));
    cbae_image_destroy(&img);
    printf("  [PASS] section_at_va\n");
}

int main(void) {
    printf("=== test_elf_loader ===\n");
    cbae_log_init(CBAE_LOG_WARN,NULL,0);
    write_elf();
    printf("  synthetic ELF: %s\n",g_tmp);
    t_valid_load();
    t_sections();
    t_va_to_ptr();
    t_symbols();
    t_imports();
    t_modinfo();
    t_relocs();
    t_bad_magic();
    t_32bit_rejected();
    t_empty_file();
    t_section_at_va();
    printf("All ELF loader tests passed.\n");
    return 0;
}
