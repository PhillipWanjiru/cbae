/**
 * @file pe_loader.c
 * @brief PE32+ binary parser — loads a Windows kernel driver (.sys) into
 *        a cbae_binary_image_t.
 */
#include "loader/pe_loader.h"
#include "loader/binary_image.h"
#include "platform/logging.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define PE_DOS_MAGIC       0x5A4D
#define PE_SIGNATURE       0x00004550
#define PE_MACHINE_AMD64   0x8664
#define PE_MACHINE_ARM64   0xAA64
#define PE_OPT_MAGIC_PE32P 0x020B
#define PE_SUBSYSTEM_NATIVE 1
#define PE_DIR_EXPORT      0
#define PE_DIR_IMPORT      1
#define PE_DIR_BASERELOC   5
#define PE_DIR_DEBUG       6
#define PE_NUM_DIRS        16
#define PE_REL_ABSOLUTE    0
#define PE_REL_HIGHLOW     3
#define PE_REL_DIR64       10
#define PE_SCN_EXEC        0x20000000
#define PE_SCN_READ        0x40000000
#define PE_SCN_WRITE       0x80000000
#define PE_SCN_CODE        0x00000020
#define PE_SCN_IDATA       0x00000040
#define PE_SCN_UDATA       0x00000080
#define PE_ORDINAL_FLAG64  (UINT64_C(1)<<63)

#pragma pack(push,1)
typedef struct { uint16_t magic; uint8_t _p[58]; uint32_t e_lfanew; } pe_dos_t;
typedef struct {
    uint16_t machine, num_sec, ts0, ts1;
    uint32_t sym_ptr, num_sym;
    uint16_t opt_sz, chars;
} pe_coff_t;
typedef struct { uint32_t rva, sz; } pe_dd_t;
typedef struct {
    uint16_t magic, maj, min;
    uint32_t code_sz, init_sz, uninit_sz, ep_rva, code_base;
    uint64_t image_base;
    uint32_t sec_align, file_align;
    uint8_t  _win[16];
    uint32_t image_sz, hdr_sz, checksum;
    uint16_t subsystem, dll_chars;
    uint8_t  _stk[32];
    uint32_t num_dirs;
    pe_dd_t  dirs[PE_NUM_DIRS];
} pe_opt64_t;
typedef struct {
    uint8_t  name[8];
    uint32_t vsz, va, rsz, roff;
    uint8_t  _rel[12];
    uint32_t chars;
} pe_shdr_t;
typedef struct { uint32_t ilt_rva,ts,fwd,name_rva,iat_rva; } pe_idesc_t;
typedef struct {
    uint32_t chars,ts; uint16_t maj,min;
    uint32_t name_rva,ord_base,nfuncs,nnames,funcs_rva,names_rva,ords_rva;
} pe_edir_t;
typedef struct { uint32_t prva,bsz; } pe_rblk_t;
typedef struct {
    uint32_t chars,ts; uint16_t maj,min;
    uint32_t type,dsz,rva,foff;
} pe_dbgdir_t;
typedef struct { uint32_t sig; uint8_t guid[16]; uint32_t age; char fn[1]; } cv_pdb_t;
#pragma pack(pop)

static const uint8_t *rptr(const uint8_t *b, cbae_size_t fsz, uint32_t rva,
                             const pe_shdr_t *s, uint16_t n) {
    for (uint16_t i=0;i<n;i++) {
        uint32_t vsz = s[i].vsz ? s[i].vsz : s[i].rsz;
        if (rva>=s[i].va && rva<s[i].va+vsz) {
            uint32_t off = s[i].roff+(rva-s[i].va);
            if ((cbae_size_t)off>=fsz) return NULL;
            return b+off;
        }
    }
    return NULL;
}

static uint32_t sec_flags(uint32_t ch) {
    uint32_t f=0;
    if(ch&PE_SCN_EXEC)  f|=CBAE_SEC_EXEC;
    if(ch&PE_SCN_READ)  f|=CBAE_SEC_READ;
    if(ch&PE_SCN_WRITE) f|=CBAE_SEC_WRITE;
    if(ch&PE_SCN_IDATA) f|=CBAE_SEC_INIT;
    if(ch&PE_SCN_UDATA) f|=CBAE_SEC_BSS;
    return f;
}

static cbae_err_t do_sections(cbae_binary_image_t *img, const pe_shdr_t *h,
                                uint16_t n, uint64_t ib) {
    img->sections = CBAE_ARENA_ALLOC_N(&img->arena, cbae_section_t, n);
    if(!img->sections) CBAE_RETURN_ERR(CBAE_ERR_OOM,"sections");
    img->section_count = n;
    for(uint16_t i=0;i<n;i++) {
        cbae_section_t *s=&img->sections[i];
        memcpy(s->name,h[i].name,8); s->name[8]='\0';
        s->virt_addr=(cbae_addr_t)(ib+h[i].va);
        s->virt_size=h[i].vsz?h[i].vsz:h[i].rsz;
        s->file_offset=h[i].roff; s->file_size=h[i].rsz;
        s->flags=sec_flags(h[i].chars);
        if(h[i].roff&&h[i].rsz&&(cbae_size_t)(h[i].roff+h[i].rsz)<=img->file_size)
            s->data=img->file_data+h[i].roff;
    }
    return CBAE_OK;
}

static cbae_err_t do_imports(cbae_binary_image_t *img, const pe_dd_t *dir,
                               const pe_shdr_t *sh, uint16_t nsec, uint64_t ib) {
    if(!dir->rva||!dir->sz) return CBAE_OK;
    const pe_idesc_t *desc=(const pe_idesc_t*)rptr(img->file_data,img->file_size,
                                                     dir->rva,sh,nsec);
    if(!desc) return CBAE_OK;
    uint32_t total=0;
    for(const pe_idesc_t *d=desc;d->name_rva;d++) {
        const uint64_t *ilt=(const uint64_t*)rptr(img->file_data,img->file_size,
                                                    d->ilt_rva?d->ilt_rva:d->iat_rva,sh,nsec);
        if(ilt) for(const uint64_t *e=ilt;*e;e++) total++;
    }
    if(!total) return CBAE_OK;
    img->imports=CBAE_ARENA_ALLOC_N(&img->arena,cbae_import_entry_t,total);
    if(!img->imports) CBAE_RETURN_ERR(CBAE_ERR_OOM,"imports");
    uint32_t idx=0;
    for(const pe_idesc_t *d=desc;d->name_rva;d++) {
        const char *dll=(const char*)rptr(img->file_data,img->file_size,d->name_rva,sh,nsec);
        if(!dll) continue;
        const uint64_t *ilt=(const uint64_t*)rptr(img->file_data,img->file_size,
                                                    d->ilt_rva?d->ilt_rva:d->iat_rva,sh,nsec);
        if(!ilt) continue;
        uint32_t ent=0;
        for(const uint64_t *e=ilt;*e;e++,ent++) {
            cbae_import_entry_t *imp=&img->imports[idx++];
            memset(imp,0,sizeof(*imp));
            strncpy(imp->module,dll,CBAE_IMPORT_MODULE_MAX-1);
            imp->iat_va=(cbae_addr_t)(ib+d->iat_rva+ent*sizeof(uint64_t));
            imp->rela_offset=(cbae_off_t)CBAE_ADDR_INVALID;
            if(*e & PE_ORDINAL_FLAG64) {
                imp->ordinal=(uint16_t)(*e&0xFFFF);
                imp->state=CBAE_IMPORT_BY_ORDINAL;
                snprintf(imp->name,CBAE_IMPORT_NAME_MAX,"ord#%u",imp->ordinal);
            } else {
                const uint8_t *hn=rptr(img->file_data,img->file_size,
                                        (uint32_t)(*e&0x7FFFFFFF),sh,nsec);
                if(hn) {
                    imp->hint=*(const uint16_t*)hn;
                    strncpy(imp->name,(const char*)(hn+2),CBAE_IMPORT_NAME_MAX-1);
                    imp->state=CBAE_IMPORT_BY_NAME;
                }
            }
            imp->table_index=idx-1;
        }
    }
    img->import_count=idx;
    LOG_DEBUG("  parsed %u imports",idx);
    return CBAE_OK;
}

static cbae_err_t do_exports(cbae_binary_image_t *img, const pe_dd_t *dir,
                               const pe_shdr_t *sh, uint16_t nsec, uint64_t ib) {
    if(!dir->rva||!dir->sz) return CBAE_OK;
    const pe_edir_t *ed=(const pe_edir_t*)rptr(img->file_data,img->file_size,
                                                 dir->rva,sh,nsec);
    if(!ed||!ed->nnames) return CBAE_OK;
    uint32_t base=img->symbol_count;
    cbae_symbol_t *syms=CBAE_ARENA_ALLOC_N(&img->arena,cbae_symbol_t,base+ed->nnames);
    if(!syms) CBAE_RETURN_ERR(CBAE_ERR_OOM,"export syms");
    if(img->symbols&&base) memcpy(syms,img->symbols,base*sizeof(cbae_symbol_t));
    img->symbols=syms;
    const uint32_t *names=(const uint32_t*)rptr(img->file_data,img->file_size,ed->names_rva,sh,nsec);
    const uint16_t *ords =(const uint16_t*)rptr(img->file_data,img->file_size,ed->ords_rva,sh,nsec);
    const uint32_t *funcs=(const uint32_t*)rptr(img->file_data,img->file_size,ed->funcs_rva,sh,nsec);
    if(!names||!ords||!funcs) return CBAE_OK;
    for(uint32_t i=0;i<ed->nnames;i++) {
        cbae_symbol_t *sym=&img->symbols[base+i];
        memset(sym,0,sizeof(*sym));
        const char *nm=(const char*)rptr(img->file_data,img->file_size,names[i],sh,nsec);
        if(nm) strncpy(sym->name,nm,CBAE_SYM_NAME_MAX-1);
        sym->address=(cbae_addr_t)(ib+funcs[ords[i]]);
        sym->type=CBAE_SYM_EXPORT; sym->binding=CBAE_BIND_GLOBAL;
        sym->kind=CBAE_KIND_FUNCTION; sym->table_index=base+i;
    }
    img->symbol_count+=ed->nnames;
    return CBAE_OK;
}

static cbae_err_t do_relocs(cbae_binary_image_t *img, const pe_dd_t *dir,
                              const pe_shdr_t *sh, uint16_t nsec, uint64_t ib) {
    if(!dir->rva||!dir->sz) return CBAE_OK;
    const uint8_t *rd=rptr(img->file_data,img->file_size,dir->rva,sh,nsec);
    if(!rd) return CBAE_OK;
    const uint8_t *end=rd+dir->sz; uint32_t total=0;
    for(const uint8_t *c=rd; c+sizeof(pe_rblk_t)<=end;) {
        const pe_rblk_t *b=(const pe_rblk_t*)c;
        if(b->bsz<sizeof(pe_rblk_t)) break;
        total+=(b->bsz-sizeof(pe_rblk_t))/2; c+=b->bsz;
    }
    if(!total) return CBAE_OK;
    img->relocations=CBAE_ARENA_ALLOC_N(&img->arena,cbae_relocation_t,total);
    if(!img->relocations) CBAE_RETURN_ERR(CBAE_ERR_OOM,"relocs");
    uint32_t idx=0;
    for(const uint8_t *c=rd; c+sizeof(pe_rblk_t)<=end;) {
        const pe_rblk_t *b=(const pe_rblk_t*)c;
        if(b->bsz<sizeof(pe_rblk_t)) break;
        uint32_t n=(b->bsz-sizeof(pe_rblk_t))/2;
        const uint16_t *ents=(const uint16_t*)(c+sizeof(pe_rblk_t));
        for(uint32_t i=0;i<n;i++) {
            uint8_t rt=(uint8_t)(ents[i]>>12); uint16_t ro=ents[i]&0x0FFF;
            cbae_relocation_t *r=&img->relocations[idx];
            memset(r,0,sizeof(*r));
            r->page_rva=b->prva;
            r->target_va=(cbae_addr_t)(ib+b->prva+ro);
            r->type=(rt==PE_REL_ABSOLUTE)?CBAE_RELOC_NOP:
                    (rt==PE_REL_HIGHLOW)?CBAE_RELOC_ABS32:
                    (rt==PE_REL_DIR64)?CBAE_RELOC_ABS64:CBAE_RELOC_UNKNOWN;
            r->table_index=idx++;
        }
        c+=b->bsz;
    }
    img->reloc_count=idx;
    LOG_DEBUG("  parsed %u relocs",idx);
    return CBAE_OK;
}

static void do_debug(cbae_binary_image_t *img, const pe_dd_t *dir,
                      const pe_shdr_t *sh, uint16_t nsec) {
    if(!dir->rva||!dir->sz) return;
    const pe_dbgdir_t *dd=(const pe_dbgdir_t*)rptr(img->file_data,img->file_size,
                                                     dir->rva,sh,nsec);
    if(!dd) return;
    uint32_t n=dir->sz/sizeof(pe_dbgdir_t);
    for(uint32_t i=0;i<n;i++) {
        if(dd[i].type==2 && dd[i].foff+4<img->file_size) {
            const cv_pdb_t *cv=(const cv_pdb_t*)(img->file_data+dd[i].foff);
            if(cv->sig==0x53445352)
                strncpy(img->meta.pe.pdb_path,cv->fn,sizeof(img->meta.pe.pdb_path)-1);
        }
    }
}

cbae_err_t cbae_pe_load(const char *path, cbae_binary_image_t **out) {
    if(!path||!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID,"null arg");
    LOG_INFO("PE load: %s",path);
    cbae_binary_image_t *img=NULL;
    cbae_err_t err=cbae_image_create(0,&img);
    if(err!=CBAE_OK) return err;
    strncpy(img->path,path,sizeof(img->path)-1);
    img->format=CBAE_FMT_PE32PLUS; img->os_origin=CBAE_OS_WINDOWS;
    int fd=open(path,O_RDONLY);
    if(fd<0){cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_IO,"open failed");}
    struct stat st;
    if(fstat(fd,&st)<0||(size_t)st.st_size<sizeof(pe_dos_t)+4){
        close(fd);cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_PARSE,"file too small");}
    const uint8_t *data=(const uint8_t*)mmap(NULL,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
    if(data==MAP_FAILED){close(fd);cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_IO,"mmap failed");}
    img->file_data=data; img->file_size=(cbae_size_t)st.st_size; img->mmap_fd=fd;
    const pe_dos_t *dos=(const pe_dos_t*)data;
    if(dos->magic!=PE_DOS_MAGIC){cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_PARSE,"bad MZ");}
    if(dos->e_lfanew+4+sizeof(pe_coff_t)>img->file_size){
        cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_PARSE,"e_lfanew OOB");}
    const uint32_t *sig=(const uint32_t*)(data+dos->e_lfanew);
    if(*sig!=PE_SIGNATURE){cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_PARSE,"bad PE sig");}
    const pe_coff_t *coff=(const pe_coff_t*)(data+dos->e_lfanew+4);
    img->arch=(coff->machine==PE_MACHINE_AMD64)?CBAE_ARCH_X86_64:
              (coff->machine==PE_MACHINE_ARM64)?CBAE_ARCH_ARM64:CBAE_ARCH_UNKNOWN;
    const pe_opt64_t *opt=(const pe_opt64_t*)((const uint8_t*)coff+sizeof(pe_coff_t));
    if(opt->magic!=PE_OPT_MAGIC_PE32P){
        cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_PARSE,"not PE32+");}
    uint64_t ib=opt->image_base;
    img->load_base=(cbae_addr_t)ib; img->entry_point=(cbae_addr_t)(ib+opt->ep_rva);
    img->meta.pe.image_base=ib; img->meta.pe.image_size=opt->image_sz;
    img->meta.pe.subsystem=opt->subsystem; img->meta.pe.checksum=opt->checksum;
    img->meta.pe.is_driver=(opt->subsystem==PE_SUBSYSTEM_NATIVE);
    const pe_shdr_t *sh=(const pe_shdr_t*)((const uint8_t*)opt+coff->opt_sz);
    if((const uint8_t*)sh+coff->num_sec*sizeof(pe_shdr_t)>data+img->file_size){
        cbae_image_destroy(&img);CBAE_RETURN_ERR(CBAE_ERR_PARSE,"shdr OOB");}
    if((err=do_sections(img,sh,coff->num_sec,ib))!=CBAE_OK){cbae_image_destroy(&img);return err;}
    if((err=do_imports(img,&opt->dirs[PE_DIR_IMPORT],sh,coff->num_sec,ib))!=CBAE_OK){cbae_image_destroy(&img);return err;}
    if((err=do_exports(img,&opt->dirs[PE_DIR_EXPORT],sh,coff->num_sec,ib))!=CBAE_OK){cbae_image_destroy(&img);return err;}
    if((err=do_relocs(img,&opt->dirs[PE_DIR_BASERELOC],sh,coff->num_sec,ib))!=CBAE_OK){cbae_image_destroy(&img);return err;}
    if(opt->num_dirs>(uint32_t)PE_DIR_DEBUG)
        do_debug(img,&opt->dirs[PE_DIR_DEBUG],sh,coff->num_sec);
    if((err=cbae_image_build_indexes(img))!=CBAE_OK){cbae_image_destroy(&img);return err;}
    cbae_image_log_summary(img);
    *out=img;
    LOG_INFO("PE load complete: %u sections %u imports %u relocs",
             img->section_count,img->import_count,img->reloc_count);
    return CBAE_OK;
}
