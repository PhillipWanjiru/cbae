/**
 * @file test_pe_loader.c
 * @brief Unit tests for the PE32+ binary loader using a synthetic binary.
 */
#include "loader/pe_loader.h"
#include "loader/binary_image.h"
#include "platform/logging.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* ── PE constants (local) ────────────────────────────────────────────────── */
#define DOS_MAGIC        0x5A4D
#define PE_SIG           0x00004550
#define OPT_PE32P        0x020B
#define MACH_AMD64       0x8664
#define SUBSYS_NATIVE    1
#define IBASE            UINT64_C(0xFFFFF80000000000)
#define TEXT_RVA         0x1000u
#define TEXT_SZ          0x200u
#define DATA_RVA         0x2000u
#define DATA_SZ          0x100u
#define IMP_RVA          0x3000u
#define RELOC_RVA        0x4000u
#define FILE_SZ          0xC00u

/* ── Packed PE structs ───────────────────────────────────────────────────── */
#pragma pack(push,1)
typedef struct { uint16_t magic; uint8_t _[58]; uint32_t lfanew; } t_dos;
typedef struct {
    uint16_t machine,nsec,ts0,ts1; uint32_t sp,ns; uint16_t optsz,chars;
} t_coff;
typedef struct { uint32_t rva,sz; } t_dd;
typedef struct {
    uint16_t magic,ml,mn; uint32_t cs,is,us,ep,cb;
    uint64_t ibase;
    uint32_t sa,fa; uint8_t _w[16];
    uint32_t imgsz,hdrsz,ck; uint16_t sub,dc;
    uint8_t _s[32]; uint32_t ndirs; t_dd dirs[16];
} t_opt;
typedef struct {
    uint8_t name[8]; uint32_t vsz,va,rsz,roff; uint8_t _[12]; uint32_t chars;
} t_sec;
typedef struct { uint32_t ilt,ts,fwd,nrva,iat; } t_idesc;
typedef struct { uint32_t prva,bsz; } t_rblk;
#pragma pack(pop)

static char g_tmp[256];
static void cleanup(void){ if(g_tmp[0]) unlink(g_tmp); }

static uint8_t g_buf[FILE_SZ];

static void build_pe(void) {
    memset(g_buf,0,FILE_SZ);

    /* DOS header */
    t_dos *dos=(t_dos*)g_buf; dos->magic=DOS_MAGIC; dos->lfanew=0x40;

    /* PE sig */
    *(uint32_t*)(g_buf+0x40)=PE_SIG;

    /* COFF */
    t_coff *coff=(t_coff*)(g_buf+0x44);
    coff->machine=MACH_AMD64; coff->nsec=4;
    coff->optsz=(uint16_t)sizeof(t_opt); coff->chars=0x0002;

    /* Optional */
    t_opt *opt=(t_opt*)(g_buf+0x44+sizeof(t_coff));
    opt->magic=OPT_PE32P; opt->ep=TEXT_RVA; opt->ibase=IBASE;
    opt->sa=0x1000; opt->fa=0x200; opt->imgsz=0x6000; opt->hdrsz=0x400;
    opt->sub=SUBSYS_NATIVE; opt->ndirs=16;
    opt->dirs[1].rva=IMP_RVA;   opt->dirs[1].sz=3*20;   /* import */
    opt->dirs[5].rva=RELOC_RVA; opt->dirs[5].sz=sizeof(t_rblk)+4*2; /* reloc */

    /* Section table starts after coff+opt */
    t_sec *secs=(t_sec*)(g_buf+0x44+sizeof(t_coff)+sizeof(t_opt));

    /* .text */
    memcpy(secs[0].name,".text\0\0\0",8);
    secs[0].vsz=TEXT_SZ; secs[0].va=TEXT_RVA;
    secs[0].rsz=TEXT_SZ; secs[0].roff=0x400;
    secs[0].chars=0x60000020;

    /* .data */
    memcpy(secs[1].name,".data\0\0\0",8);
    secs[1].vsz=DATA_SZ; secs[1].va=DATA_RVA;
    secs[1].rsz=DATA_SZ; secs[1].roff=0x600;
    secs[1].chars=0xC0000040;

    /* .idata */
    memcpy(secs[2].name,".idata\0\0",8);
    secs[2].vsz=0x400; secs[2].va=IMP_RVA;
    secs[2].rsz=0x400; secs[2].roff=0x800;
    secs[2].chars=0x40000040;

    /* .reloc */
    memcpy(secs[3].name,".reloc\0\0",8);
    secs[3].vsz=0x200; secs[3].va=RELOC_RVA;
    secs[3].rsz=0x200; secs[3].roff=0xA00;
    secs[3].chars=0x42000040;

    /* .text = NOP sled */
    memset(g_buf+0x400,0x90,TEXT_SZ);

    /* Import tables */
    uint8_t *imp=g_buf+0x800;
    uint32_t dll0_off=3*20, dll1_off=dll0_off+16;
    uint32_t hn0_off=dll1_off+8, hn1_off=hn0_off+24, hn2_off=hn1_off+24;
    uint32_t ilt0_off=hn2_off+32, ilt1_off=ilt0_off+24;
    uint32_t iat0_off=ilt1_off+16, iat1_off=iat0_off+24;

    strcpy((char*)(imp+dll0_off),"ntoskrnl.exe");
    strcpy((char*)(imp+dll1_off),"HAL.dll");

    *(uint16_t*)(imp+hn0_off)=0x100;
    strcpy((char*)(imp+hn0_off+2),"ExAllocatePoolWithTag");
    *(uint16_t*)(imp+hn1_off)=0x200;
    strcpy((char*)(imp+hn1_off+2),"IoCreateDevice");
    *(uint16_t*)(imp+hn2_off)=0x010;
    strcpy((char*)(imp+hn2_off+2),"KeStallExecutionProcessor");

    /* the import lookup tables are packed, so these offsets are not 8-aligned: memcpy, not a cast store */
    const uint64_t ilt_e0=IMP_RVA+hn0_off, ilt_e1=IMP_RVA+hn1_off, ilt_e2=IMP_RVA+hn2_off;
    memcpy(imp+ilt0_off+0,&ilt_e0,8);
    memcpy(imp+ilt0_off+8,&ilt_e1,8);
    memcpy(imp+ilt1_off+0,&ilt_e2,8);
    memcpy(imp+iat0_off,imp+ilt0_off,16);
    memcpy(imp+iat1_off,imp+ilt1_off,8);

    t_idesc *descs=(t_idesc*)imp;
    descs[0].ilt=IMP_RVA+ilt0_off; descs[0].nrva=IMP_RVA+dll0_off; descs[0].iat=IMP_RVA+iat0_off;
    descs[1].ilt=IMP_RVA+ilt1_off; descs[1].nrva=IMP_RVA+dll1_off; descs[1].iat=IMP_RVA+iat1_off;

    /* Base relocs */
    t_rblk *rb=(t_rblk*)(g_buf+0xA00);
    rb->prva=TEXT_RVA; rb->bsz=sizeof(t_rblk)+4*2;
    uint16_t *ents=(uint16_t*)(g_buf+0xA00+sizeof(t_rblk));
    ents[0]=(uint16_t)((10<<12)|0x000);
    ents[1]=(uint16_t)((10<<12)|0x008);
    ents[2]=0; ents[3]=0;
}

static void write_pe(void) {
    build_pe();
    snprintf(g_tmp,sizeof(g_tmp),"/tmp/cbae_pe_test_%d.sys",(int)getpid());
    atexit(cleanup);
    FILE *f=fopen(g_tmp,"wb");
    assert(f); fwrite(g_buf,1,FILE_SZ,f); fclose(f);
}

/* ── Tests ───────────────────────────────────────────────────────────────── */
static void t_valid_load(void) {
    cbae_binary_image_t *img=NULL;
    assert(cbae_pe_load(g_tmp,&img)==CBAE_OK);
    assert(img && img->format==CBAE_FMT_PE32PLUS);
    assert(img->arch==CBAE_ARCH_X86_64);
    assert(img->os_origin==CBAE_OS_WINDOWS);
    assert(img->meta.pe.is_driver==true);
    assert(img->meta.pe.image_base==IBASE);
    assert(img->entry_point==IBASE+TEXT_RVA);
    cbae_image_destroy(&img); assert(!img);
    printf("  [PASS] valid PE32+ load\n");
}

static void t_sections(void) {
    cbae_binary_image_t *img=NULL;
    cbae_pe_load(g_tmp,&img); assert(img);
    assert(img->section_count==4);
    cbae_section_t *tx=cbae_image_section_by_name(img,".text");
    assert(tx && cbae_section_is_code(tx));
    cbae_section_t *da=cbae_image_section_by_name(img,".data");
    assert(da && (da->flags&CBAE_SEC_WRITE) && !(da->flags&CBAE_SEC_EXEC));
    cbae_image_destroy(&img);
    printf("  [PASS] sections (count=4, .text exec, .data writable)\n");
}

static void t_va_to_ptr(void) {
    cbae_binary_image_t *img=NULL;
    cbae_pe_load(g_tmp,&img); assert(img);
    cbae_addr_t va=IBASE+TEXT_RVA;
    const uint8_t *p=cbae_image_va_to_ptr(img,va);
    assert(p && *p==0x90);
    assert(!cbae_image_va_to_ptr(img,va+TEXT_SZ+1));
    cbae_image_destroy(&img);
    printf("  [PASS] VA-to-ptr (.text NOP, past-end=NULL)\n");
}

static void t_imports(void) {
    cbae_binary_image_t *img=NULL;
    cbae_pe_load(g_tmp,&img); assert(img);
    assert(img->import_count==3);
    cbae_import_entry_t *a=cbae_image_import_by_name(img,"ExAllocatePoolWithTag");
    assert(a && !strcmp(a->module,"ntoskrnl.exe") && a->state==CBAE_IMPORT_BY_NAME);
    cbae_import_entry_t *k=cbae_image_import_by_name(img,"KeStallExecutionProcessor");
    assert(k && !strcmp(k->module,"HAL.dll"));
    cbae_image_destroy(&img);
    printf("  [PASS] imports (count=3, names+modules correct)\n");
}

static void t_iat_lookup(void) {
    cbae_binary_image_t *img=NULL;
    cbae_pe_load(g_tmp,&img); assert(img);
    cbae_import_entry_t *a=cbae_image_import_by_name(img,"ExAllocatePoolWithTag");
    assert(a && cbae_import_has_iat(a));
    cbae_import_entry_t *found=cbae_image_import_at_iat(img,a->iat_va);
    assert(found && !strcmp(found->name,"ExAllocatePoolWithTag"));
    cbae_image_destroy(&img);
    printf("  [PASS] IAT lookup: CALL [iat_va] -> ExAllocatePoolWithTag\n");
}

static void t_relocs(void) {
    cbae_binary_image_t *img=NULL;
    cbae_pe_load(g_tmp,&img); assert(img);
    assert(img->reloc_count>=2);
    uint32_t abs64=0;
    for(uint32_t i=0;i<img->reloc_count;i++)
        if(img->relocations[i].type==CBAE_RELOC_ABS64) abs64++;
    assert(abs64==2);
    cbae_image_destroy(&img);
    printf("  [PASS] relocs (>=2 entries, 2 ABS64)\n");
}

static void t_bad_magic(void) {
    char p[256]; snprintf(p,sizeof(p),"/tmp/cbae_bad_%d.sys",(int)getpid());
    FILE *f=fopen(p,"wb"); assert(f);
    uint8_t junk[64]; memset(junk,0xCC,sizeof(junk));
    fwrite(junk,1,sizeof(junk),f); fclose(f);
    cbae_binary_image_t *img=NULL;
    assert(cbae_pe_load(p,&img)==CBAE_ERR_PARSE);
    assert(!img); unlink(p);
    printf("  [PASS] bad MZ magic -> CBAE_ERR_PARSE\n");
}

static void t_empty_file(void) {
    char p[256]; snprintf(p,sizeof(p),"/tmp/cbae_empty_%d.sys",(int)getpid());
    FILE *f=fopen(p,"wb"); fclose(f);
    cbae_binary_image_t *img=NULL;
    cbae_err_t e=cbae_pe_load(p,&img);
    assert(e==CBAE_ERR_PARSE||e==CBAE_ERR_IO); assert(!img); unlink(p);
    printf("  [PASS] empty file -> CBAE_ERR_PARSE/IO\n");
}

static void t_section_at_va(void) {
    cbae_binary_image_t *img=NULL;
    cbae_pe_load(g_tmp,&img); assert(img);
    cbae_section_t *s=cbae_image_section_at_va(img,IBASE+TEXT_RVA+4);
    assert(s && !strcmp(s->name,".text"));
    assert(!cbae_image_section_at_va(img,0xDEADBEEF));
    cbae_image_destroy(&img);
    printf("  [PASS] section_at_va\n");
}

int main(void) {
    printf("=== test_pe_loader ===\n");
    cbae_log_init(CBAE_LOG_WARN,NULL,0);
    write_pe();
    printf("  synthetic PE: %s\n",g_tmp);
    t_valid_load();
    t_sections();
    t_va_to_ptr();
    t_imports();
    t_iat_lookup();
    t_relocs();
    t_bad_magic();
    t_empty_file();
    t_section_at_va();
    printf("All PE loader tests passed.\n");
    return 0;
}
