/**
 * @file elf_loader.c
 * @brief ELF64 binary parser — loads a Linux kernel module (.ko) into
 *        a cbae_binary_image_t.
 */
#include "loader/elf_loader.h"
#include "loader/binary_image.h"
#include "platform/logging.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* ── ELF constants ───────────────────────────────────────────────────────── */
#define ELF_MAGIC      0x464C457F
#define ELFCLASS64     2
#define ELFDATA2LSB    1
#define ET_REL         1
#define EM_X86_64      62
#define EM_AARCH64     183
#define SHT_NULL       0
#define SHT_PROGBITS   1
#define SHT_SYMTAB     2
#define SHT_STRTAB     3
#define SHT_RELA       4
#define SHT_NOBITS     8
#define SHF_WRITE      0x1
#define SHF_ALLOC      0x2
#define SHF_EXECINSTR  0x4
#define STB_LOCAL      0
#define STB_GLOBAL     1
#define STB_WEAK       2
#define STT_FUNC       2
#define STT_OBJECT     1
#define STT_FILE       4
#define STT_SECTION    3
#define SHN_UNDEF      0
#define R_X86_64_64    1
#define R_X86_64_PC32  2
#define R_X86_64_PLT32 4
#define R_X86_64_32S   11
#define R_X86_64_GOTPCRELX 41
#define ELF64_ST_BIND(i) ((i)>>4)
#define ELF64_ST_TYPE(i) ((i)&0xF)
#define ELF64_R_SYM(i)   ((uint32_t)((i)>>32))
#define ELF64_R_TYPE(i)  ((uint32_t)((i)&0xFFFFFFFF))

#pragma pack(push,1)
typedef struct {
    uint8_t  ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint64_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t ehsz, phesz, phnum, shesz, shnum, shstrndx;
} elf64_hdr_t;
typedef struct {
    uint32_t name, type;
    uint64_t flags, addr, offset, size;
    uint32_t link, info;
    uint64_t addralign, entsize;
} elf64_shdr_t;
typedef struct {
    uint32_t name; uint8_t info, other; uint16_t shndx;
    uint64_t value, size;
} elf64_sym_t;
typedef struct { uint64_t offset, info; int64_t addend; } elf64_rela_t;
#pragma pack(pop)

/* ── Helpers ─────────────────────────────────────────────────────────────── */
static const void *elfptr(const uint8_t *b, cbae_size_t fsz,
                            uint64_t off, uint64_t sz) {
    if(off>=fsz||sz>fsz-off) return NULL;
    return b+off;
}

static const char *shname(const elf64_hdr_t *h, const elf64_shdr_t *s,
                            const uint8_t *b, cbae_size_t fsz, uint16_t idx) {
    if(!h->shstrndx||h->shstrndx>=h->shnum) return "";
    const elf64_shdr_t *ss=&s[h->shstrndx];
    if(s[idx].name>=ss->size) return "";
    const char *st=(const char*)elfptr(b,fsz,ss->offset,ss->size);
    return st ? st+s[idx].name : "";
}

static const char *strtab_get(const uint8_t *b, cbae_size_t fsz,
                                const elf64_shdr_t *sh, uint32_t off) {
    if(!sh||off>=sh->size) return "";
    const char *s=(const char*)elfptr(b,fsz,sh->offset,sh->size);
    return s ? s+off : "";
}

static uint32_t elf_secflags(uint64_t f, uint32_t t) {
    uint32_t r=0;
    if(f&SHF_EXECINSTR) r|=CBAE_SEC_EXEC;
    if(f&SHF_ALLOC)     r|=CBAE_SEC_READ;
    if(f&SHF_WRITE)     r|=CBAE_SEC_WRITE;
    if(t==SHT_NOBITS)   r|=CBAE_SEC_BSS;
    if(t==SHT_RELA)     r|=CBAE_SEC_RELOC;
    return r;
}

static cbae_sym_binding_t elf_bind(uint8_t info) {
    switch(ELF64_ST_BIND(info)) {
        case STB_GLOBAL: return CBAE_BIND_GLOBAL;
        case STB_WEAK:   return CBAE_BIND_WEAK;
        default:         return CBAE_BIND_LOCAL;
    }
}

static cbae_sym_kind_t elf_kind(uint8_t info) {
    switch(ELF64_ST_TYPE(info)) {
        case STT_FUNC:   return CBAE_KIND_FUNCTION;
        case STT_OBJECT: return CBAE_KIND_OBJECT;
        default:         return CBAE_KIND_NOTYPE;
    }
}

static cbae_reloc_type_t elf_rtype(uint32_t t) {
    switch(t) {
        case R_X86_64_64:       return CBAE_RELOC_64;
        case R_X86_64_PC32:     return CBAE_RELOC_PC32;
        case R_X86_64_PLT32:    return CBAE_RELOC_PLT32;
        case R_X86_64_32S:      return CBAE_RELOC_32S;
        case R_X86_64_GOTPCRELX:return CBAE_RELOC_GOTPCREL;
        default:                return CBAE_RELOC_UNKNOWN;
    }
}

/* ── Sub-parsers ─────────────────────────────────────────────────────────── */
static cbae_err_t do_sections(cbae_binary_image_t *img,
                                const elf64_hdr_t *h, const elf64_shdr_t *s,
                                const uint8_t *b, cbae_size_t fsz) {
    uint32_t cnt=0;
    for(uint16_t i=0;i<h->shnum;i++) if(s[i].type!=SHT_NULL) cnt++;
    if(!cnt) return CBAE_OK;
    img->sections=CBAE_ARENA_ALLOC_N(&img->arena,cbae_section_t,cnt);
    if(!img->sections) CBAE_RETURN_ERR(CBAE_ERR_OOM,"elf sections");
    uint32_t idx=0;
    for(uint16_t i=0;i<h->shnum;i++) {
        if(s[i].type==SHT_NULL) continue;
        cbae_section_t *sec=&img->sections[idx];
        memset(sec,0,sizeof(*sec));
        const char *nm=shname(h,s,b,fsz,i);
        strncpy(sec->name,nm,CBAE_SEC_NAME_MAX-1);
        sec->virt_addr = s[i].addr ? (cbae_addr_t)s[i].addr
                                   : (cbae_addr_t)i*0x400000ULL;
        sec->virt_size   = (cbae_size_t)s[i].size;
        sec->file_offset = (cbae_off_t)s[i].offset;
        sec->file_size   = (s[i].type==SHT_NOBITS)?0:(cbae_size_t)s[i].size;
        sec->flags       = elf_secflags(s[i].flags,s[i].type);
        if(s[i].type!=SHT_NOBITS&&s[i].size)
            sec->data=(const uint8_t*)elfptr(b,fsz,s[i].offset,s[i].size);
        idx++;
    }
    img->section_count=idx;
    return CBAE_OK;
}

static cbae_err_t do_symtab(cbae_binary_image_t *img,
                              const elf64_hdr_t *h, const elf64_shdr_t *s,
                              const uint8_t *b, cbae_size_t fsz) {
    const elf64_shdr_t *symsec=NULL, *strsec=NULL;
    for(uint16_t i=0;i<h->shnum;i++) {
        if(s[i].type==SHT_SYMTAB) {
            symsec=&s[i];
            if(s[i].link<h->shnum) strsec=&s[s[i].link];
            break;
        }
    }
    if(!symsec) return CBAE_OK;
    uint64_t esz=symsec->entsize?symsec->entsize:sizeof(elf64_sym_t);
    uint32_t cnt=(uint32_t)(symsec->size/esz);
    const elf64_sym_t *syms=(const elf64_sym_t*)elfptr(b,fsz,symsec->offset,symsec->size);
    if(!syms) return CBAE_OK;
    img->symbols=CBAE_ARENA_ALLOC_N(&img->arena,cbae_symbol_t,cnt);
    if(!img->symbols) CBAE_RETURN_ERR(CBAE_ERR_OOM,"elf syms");
    uint32_t idx=0;
    for(uint32_t i=0;i<cnt;i++) {
        /* ELF spec: symtab[0] is always the reserved null entry (all
         * zero fields) and must be skipped by every conformant parser.
         * Without this check it would be misclassified as an import
         * (shndx==SHN_UNDEF==0) with an empty name.                    */
        if(i==0) continue;
        int stype=ELF64_ST_TYPE(syms[i].info);
        if(stype==STT_FILE||stype==STT_SECTION) continue;
        cbae_symbol_t *sym=&img->symbols[idx];
        memset(sym,0,sizeof(*sym));
        const char *nm=strtab_get(b,fsz,strsec,syms[i].name);
        strncpy(sym->name,nm,CBAE_SYM_NAME_MAX-1);
        strncpy(sym->source,"kernel",CBAE_SYM_SOURCE_MAX-1);
        if(syms[i].shndx==SHN_UNDEF) {
            sym->type=CBAE_SYM_IMPORT; sym->address=CBAE_ADDR_INVALID;
        } else {
            sym->type=CBAE_SYM_LOCAL;
            if(syms[i].shndx<h->shnum&&syms[i].value) {
                cbae_addr_t base=s[syms[i].shndx].addr ?
                    (cbae_addr_t)s[syms[i].shndx].addr :
                    (cbae_addr_t)syms[i].shndx*0x400000ULL;
                sym->address=base+(cbae_addr_t)syms[i].value;
            } else sym->address=(cbae_addr_t)syms[i].value;
        }
        sym->size=syms[i].size;
        sym->binding=elf_bind(syms[i].info);
        sym->kind=elf_kind(syms[i].info);
        sym->section_idx=syms[i].shndx;
        sym->table_index=idx;
        if(sym->binding==CBAE_BIND_GLOBAL&&sym->type==CBAE_SYM_LOCAL)
            sym->type=CBAE_SYM_EXPORT;
        idx++;
    }
    img->symbol_count=idx;
    LOG_DEBUG("  parsed %u symbols",idx);
    return CBAE_OK;
}

static cbae_err_t do_relas(cbae_binary_image_t *img,
                             const elf64_hdr_t *h, const elf64_shdr_t *s,
                             const uint8_t *b, cbae_size_t fsz) {
    /* count total rela entries and imports */
    uint32_t tot_r=0, tot_i=0;
    for(uint16_t i=0;i<h->shnum;i++) {
        if(s[i].type!=SHT_RELA) continue;
        uint64_t esz=s[i].entsize?s[i].entsize:sizeof(elf64_rela_t);
        uint32_t cnt=(uint32_t)(s[i].size/esz); tot_r+=cnt;
        if(s[i].link>=h->shnum) continue;
        const elf64_shdr_t *symsec=&s[s[i].link];
        uint64_t sesz=symsec->entsize?symsec->entsize:sizeof(elf64_sym_t);
        uint64_t scnt=symsec->size/sesz;
        const elf64_sym_t *symt=(const elf64_sym_t*)elfptr(b,fsz,symsec->offset,symsec->size);
        const elf64_rela_t *rels=(const elf64_rela_t*)elfptr(b,fsz,s[i].offset,s[i].size);
        if(!symt||!rels) continue;
        for(uint32_t j=0;j<cnt;j++) {
            uint32_t si=ELF64_R_SYM(rels[j].info);
            if(si<scnt&&symt[si].shndx==SHN_UNDEF) tot_i++;
        }
    }
    if(!tot_r) return CBAE_OK;
    img->relocations=CBAE_ARENA_ALLOC_N(&img->arena,cbae_relocation_t,tot_r);
    if(!img->relocations) CBAE_RETURN_ERR(CBAE_ERR_OOM,"relas");
    uint32_t ibase=img->import_count;
    if(tot_i) {
        cbae_import_entry_t *ni=CBAE_ARENA_ALLOC_N(&img->arena,cbae_import_entry_t,ibase+tot_i);
        if(!ni) CBAE_RETURN_ERR(CBAE_ERR_OOM,"elf imports");
        if(img->imports&&ibase) memcpy(ni,img->imports,ibase*sizeof(cbae_import_entry_t));
        img->imports=ni;
    }
    uint32_t ri=0, ii=ibase;
    for(uint16_t i=0;i<h->shnum;i++) {
        if(s[i].type!=SHT_RELA) continue;
        if(s[i].link>=h->shnum) continue;
        const elf64_shdr_t *symsec=&s[s[i].link];
        const elf64_shdr_t *strsec=(symsec->link<h->shnum)?&s[symsec->link]:NULL;
        uint64_t sesz=symsec->entsize?symsec->entsize:sizeof(elf64_sym_t);
        uint64_t scnt=symsec->size/sesz;
        const elf64_sym_t *symt=(const elf64_sym_t*)elfptr(b,fsz,symsec->offset,symsec->size);
        uint64_t esz=s[i].entsize?s[i].entsize:sizeof(elf64_rela_t);
        uint32_t cnt=(uint32_t)(s[i].size/esz);
        const elf64_rela_t *rels=(const elf64_rela_t*)elfptr(b,fsz,s[i].offset,s[i].size);
        if(!symt||!rels) continue;
        uint32_t tgt=s[i].info;
        cbae_addr_t tbase=(tgt<h->shnum)?(s[tgt].addr?(cbae_addr_t)s[tgt].addr:
                                           (cbae_addr_t)tgt*0x400000ULL):0;
        for(uint32_t j=0;j<cnt&&ri<tot_r;j++) {
            uint32_t si=ELF64_R_SYM(rels[j].info);
            uint32_t rt=ELF64_R_TYPE(rels[j].info);
            cbae_relocation_t *r=&img->relocations[ri];
            memset(r,0,sizeof(*r));
            r->target_va=tbase+(cbae_addr_t)rels[j].offset;
            r->type=elf_rtype(rt); r->addend=rels[j].addend;
            r->sym_index=si; r->table_index=ri;
            if(si<scnt&&symt[si].shndx==SHN_UNDEF&&tot_i&&ii<ibase+tot_i) {
                const char *nm=strtab_get(b,fsz,strsec,symt[si].name);
                cbae_import_entry_t *imp=&img->imports[ii];
                memset(imp,0,sizeof(*imp));
                strncpy(imp->name,nm,CBAE_IMPORT_NAME_MAX-1);
                strncpy(imp->module,"kernel",CBAE_IMPORT_MODULE_MAX-1);
                imp->iat_va=CBAE_ADDR_INVALID;
                imp->rela_offset=(cbae_off_t)rels[j].offset;
                imp->rela_type=rt; imp->state=CBAE_IMPORT_UNRESOLVED;
                imp->table_index=ii; r->references_import=true; ii++;
            }
            ri++;
        }
    }
    img->reloc_count=ri; img->import_count=ii;
    LOG_DEBUG("  parsed %u relocs %u kernel imports",ri,ii);
    return CBAE_OK;
}

static void do_modinfo(cbae_binary_image_t *img,
                        const elf64_hdr_t *h, const elf64_shdr_t *s,
                        const uint8_t *b, cbae_size_t fsz) {
    for(uint16_t i=0;i<h->shnum;i++) {
        const char *nm=shname(h,s,b,fsz,i);
        if(strcmp(nm,".modinfo")!=0) continue;
        const char *data=(const char*)elfptr(b,fsz,s[i].offset,s[i].size);
        if(!data) return;
        const char *p=data, *end=data+s[i].size;
        while(p<end&&*p) {
            const char *eq=strchr(p,'=');
            if(!eq){p+=strlen(p)+1;continue;}
            size_t kl=(size_t)(eq-p); const char *v=eq+1;
            if(!strncmp(p,"vermagic",kl))
                strncpy(img->meta.elf.kernel_version,v,sizeof(img->meta.elf.kernel_version)-1);
            else if(!strncmp(p,"license",kl))
                strncpy(img->meta.elf.module_license,v,sizeof(img->meta.elf.module_license)-1);
            else if(!strncmp(p,"author",kl))
                strncpy(img->meta.elf.module_author,v,sizeof(img->meta.elf.module_author)-1);
            else if(!strncmp(p,"description",kl))
                strncpy(img->meta.elf.module_description,v,sizeof(img->meta.elf.module_description)-1);
            p+=strlen(p)+1;
        }
        LOG_DEBUG("  modinfo: vermagic='%s' license='%s'",
                  img->meta.elf.kernel_version,img->meta.elf.module_license);
        return;
    }
}

static void do_ksymtab(cbae_binary_image_t *img,
                        const elf64_hdr_t *h, const elf64_shdr_t *s,
                        const uint8_t *b, cbae_size_t fsz) {
    for(uint16_t i=0;i<h->shnum;i++) {
        if(strcmp(shname(h,s,b,fsz,i),"__ksymtab_strings")!=0) continue;
        img->meta.elf.has_ksymtab=true;
        const char *strs=(const char*)elfptr(b,fsz,s[i].offset,s[i].size);
        if(!strs) return;
        uint32_t cnt=0;
        const char *p=strs, *end=strs+s[i].size;
        while(p<end){if(*p)cnt++;p+=strlen(p)+1;}
        if(!cnt) return;
        cbae_symbol_t *ns=CBAE_ARENA_ALLOC_N(&img->arena,cbae_symbol_t,
                                               img->symbol_count+cnt);
        if(!ns) return;
        if(img->symbols&&img->symbol_count)
            memcpy(ns,img->symbols,img->symbol_count*sizeof(cbae_symbol_t));
        img->symbols=ns;
        p=strs;
        while(p<end){
            if(!*p){p++;continue;}
            cbae_symbol_t *sym=&img->symbols[img->symbol_count++];
            memset(sym,0,sizeof(*sym));
            strncpy(sym->name,p,CBAE_SYM_NAME_MAX-1);
            sym->type=CBAE_SYM_EXPORT; sym->binding=CBAE_BIND_GLOBAL;
            sym->kind=CBAE_KIND_FUNCTION; sym->address=CBAE_ADDR_INVALID;
            p+=strlen(p)+1;
        }
        LOG_DEBUG("  __ksymtab_strings: %u exports",cnt);
        return;
    }
}

/* ── Public API ──────────────────────────────────────────────────────────── */
cbae_err_t cbae_elf_load(const char *path, cbae_binary_image_t **out) {
    if(!path||!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID,"null arg");
    LOG_INFO("ELF load: %s",path);
    cbae_binary_image_t *img=NULL;
    cbae_err_t err=cbae_image_create(0,&img);
    if(err!=CBAE_OK) return err;
    strncpy(img->path,path,sizeof(img->path)-1);
    img->format=CBAE_FMT_ELF64; img->os_origin=CBAE_OS_LINUX; img->load_base=0;
    int fd=open(path,O_RDONLY);
    if(fd<0){cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_IO,"open failed");}
    struct stat st;
    if(fstat(fd,&st)<0||(size_t)st.st_size<sizeof(elf64_hdr_t)){
        close(fd);cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_PARSE,"file too small");}
    const uint8_t *data=(const uint8_t*)mmap(NULL,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
    if(data==MAP_FAILED){close(fd);cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_IO,"mmap failed");}
    img->file_data=data; img->file_size=(cbae_size_t)st.st_size; img->mmap_fd=fd;
    const elf64_hdr_t *h=(const elf64_hdr_t*)data;
    uint32_t magic; memcpy(&magic,h->ident,4);
    if(magic!=ELF_MAGIC){cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_PARSE,"bad ELF magic");}
    if(h->ident[4]!=ELFCLASS64){cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_PARSE,"not ELF64");}
    if(h->ident[5]!=ELFDATA2LSB){cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_PARSE,"not LE");}
    img->arch=(h->machine==EM_X86_64)?CBAE_ARCH_X86_64:
              (h->machine==EM_AARCH64)?CBAE_ARCH_ARM64:CBAE_ARCH_UNKNOWN;
    if(!h->shoff||!h->shnum){cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_PARSE,"no shdrs");}
    cbae_size_t shend=(cbae_size_t)h->shoff+h->shnum*sizeof(elf64_shdr_t);
    if(shend>img->file_size){cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_PARSE,"shdr OOB");}
    const elf64_shdr_t *s=(const elf64_shdr_t*)(data+h->shoff);
    img->entry_point=(cbae_addr_t)h->entry;
    if((err=do_sections(img,h,s,data,img->file_size))!=CBAE_OK){cbae_image_destroy(&img);return err;}
    if((err=do_symtab(img,h,s,data,img->file_size))!=CBAE_OK){cbae_image_destroy(&img);return err;}
    if((err=do_relas(img,h,s,data,img->file_size))!=CBAE_OK){cbae_image_destroy(&img);return err;}
    do_modinfo(img,h,s,data,img->file_size);
    do_ksymtab(img,h,s,data,img->file_size);
    if((err=cbae_image_build_indexes(img))!=CBAE_OK){cbae_image_destroy(&img);return err;}
    cbae_image_log_summary(img);
    *out=img;
    LOG_INFO("ELF load complete: %u sections %u symbols %u imports %u relocs",
             img->section_count,img->symbol_count,img->import_count,img->reloc_count);
    return CBAE_OK;
}
