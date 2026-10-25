/* Execute original CPop-vector growth on private, relocated PE32 code.
 * Successful original CRT allocations use real HeapAlloc/HeapFree. A recording
 * allocator initializes returned storage to a declared poison pattern only.
 * No source game files or live game state are patched. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(void *)==4,"PE32 required");
#define WORD(p,o) (*(uint32_t *)((unsigned char *)(p)+(o)))
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"CHECK line %d: %s\n",__LINE__,#c); ExitProcess(2); } } while(0)
static HANDLE fixture_heap;
static unsigned char *private_image;
static unsigned relocation_count;
static unsigned char catalog[0x1000];
static unsigned char *old_array;
static unsigned char expected_old[32*0x278];
static unsigned expected_bytes,call_allocs,call_frees,total_allocs,total_frees,cases,snapshots;
static unsigned allocation_bytes,allocation_pattern;
static void *new_array;
static uint32_t *current_header;
static uint32_t old_header[3];
typedef struct {void *p;unsigned size,logical;unsigned char before[256];} source_buffer;
typedef struct {void *p;unsigned size;unsigned char expected[256];} allocation_item;
static source_buffer source_buffers[17][8];
static allocation_item allocation_plan[160];
static unsigned plan_count,free_plan_count;
static source_buffer *free_plan[160];
static unsigned vector_offsets[8]={0x7c,0x8c,0xa4,0xb4,0xcc,0xdc,0xf4,0x104};
static unsigned catalog_a_count,catalog_b_count,source_surplus,catalog_words_checked;
static unsigned copy_intermediate_free,copy_optional_index;
static unsigned factory_temp_remaining,factory_temp_total;
static void *registered_link_expected;
static uint32_t *registered_table_expected,*registered_heads_expected;
static unsigned registered_bucket_expected;
static unsigned char *image_va(unsigned va) {return private_image+va-0x400000;}
static unsigned ptr(void *p) {return (unsigned)(uintptr_t)p;}

static LPVOID WINAPI recorded_heap_alloc(HANDLE heap,DWORD flags,SIZE_T size) {
    CHECK(heap==fixture_heap && flags==0 && call_allocs<plan_count);
    CHECK(size==allocation_plan[call_allocs].size);
    void *p=HeapAlloc(heap,flags,size);CHECK(p!=NULL);
    memset(p,allocation_pattern,size);
    allocation_plan[call_allocs].p=p;
    if(call_allocs==0)new_array=p;
    call_allocs++;total_allocs++;
    return p;
}
static BOOL WINAPI recorded_heap_free(HANDLE heap,DWORD flags,LPVOID pointer) {
    if(factory_temp_remaining) {
        unsigned index=--factory_temp_remaining;allocation_item *item=&allocation_plan[index];
        CHECK(heap==fixture_heap && flags==0 && pointer==item->p);
        CHECK(call_allocs==2*factory_temp_total+1 && call_frees==factory_temp_total-1-index);
        CHECK(memcmp(pointer,item->expected,item->size)==0);
        CHECK(HeapFree(heap,flags,pointer));call_frees++;total_frees++;snapshots++;
        return TRUE;
    }
    if(copy_intermediate_free) {
        CHECK(heap==fixture_heap && flags==0 && call_frees==0 && pointer==allocation_plan[copy_optional_index+1].p);
        CHECK(memcmp(pointer,allocation_plan[copy_optional_index+1].expected,8)==0);
        void *resource=allocation_plan[copy_optional_index].p;
        CHECK(WORD(resource,0x48)==ptr(pointer) && WORD(resource,0x4c)==ptr(pointer)+8 && WORD(resource,0x50)==ptr(pointer)+8);
        CHECK(HeapFree(heap,flags,pointer));call_frees++;total_frees++;snapshots++;copy_intermediate_free=0;
        return TRUE;
    }
    CHECK(heap==fixture_heap && flags==0 && call_frees<free_plan_count+(old_array?1u:0u));
    CHECK(HeapSize(heap,0,pointer)!=(SIZE_T)-1);
    if(pointer==registered_link_expected) {
        CHECK(registered_table_expected[0]==1 && registered_heads_expected[registered_bucket_expected]==0);
        registered_link_expected=NULL;
    }
    if(call_frees<free_plan_count) {
        source_buffer *b=free_plan[call_frees];
        if(pointer!=b->p) {fprintf(stderr,"free index %u expected %p actual %p allocs %u\n",call_frees,b->p,pointer,call_allocs);for(unsigned i=0;i<plan_count;i++)if(allocation_plan[i].p==pointer)fprintf(stderr,"actual allocation index %u size %u\n",i,allocation_plan[i].size);}
        CHECK(pointer==b->p);
        CHECK(memcmp(pointer,b->before,b->size)==0);
    } else {
        CHECK(pointer==old_array);CHECK(memcmp(pointer,expected_old,expected_bytes)==0);
    }
    CHECK(memcmp(current_header,old_header,sizeof old_header)==0);
    snapshots++;
    CHECK(HeapFree(heap,flags,pointer));call_frees++;total_frees++;
    return TRUE;
}
static BOOL WINAPI recorded_switch_to_thread(void) {CHECK(0);return FALSE;}
static LONG CALLBACK unexpected_exception(EXCEPTION_POINTERS *info) {
    fprintf(stderr,"Unexpected exception %08lx at %p\n",info->ExceptionRecord->ExceptionCode,info->ExceptionRecord->ExceptionAddress);
    ExitProcess(3);return EXCEPTION_CONTINUE_SEARCH;
}
#include "native_private_image.h"

extern void *__cdecl invoke_append(void *header,void *source,void *entry);
extern void *__cdecl invoke_construct(void *object,void *type,void *entry);
extern void __cdecl invoke_register(void *object,void *key,void *entry);
extern void *__cdecl invoke_refresh(void *handle,void *entry);
extern void *__cdecl invoke_resolve_no_cache(void *handle,void *entry);
extern unsigned __cdecl invoke_unlink(void *bucket,void *node,void *entry);
__asm__(
    ".text\n.globl _invoke_append\n_invoke_append:\n"
    "pushl %edi\nmovl 8(%esp),%edi\nmovl 12(%esp),%ecx\ncall *16(%esp)\npopl %edi\nret\n"
    ".globl _invoke_construct\n_invoke_construct:\n"
    "movl 8(%esp),%edx\npushl 4(%esp)\ncall *16(%esp)\nret\n"
    ".globl _invoke_register\n_invoke_register:\n"
    "movl 4(%esp),%ecx\npushl 8(%esp)\ncall *16(%esp)\nret\n"
    ".globl _invoke_refresh\n_invoke_refresh:\n"
    "pushl %esi\nmovl 8(%esp),%esi\ncall *12(%esp)\npopl %esi\nret\n"
    ".globl _invoke_resolve_no_cache\n_invoke_resolve_no_cache:\n"
    "movl 4(%esp),%eax\ncall *8(%esp)\nret\n"
    ".globl _invoke_unlink\n_invoke_unlink:\n"
    "pushl %esi\nmovl 8(%esp),%esi\nmovl 16(%esp),%eax\npushl 12(%esp)\ncall *%eax\nmovzbl %al,%eax\npopl %esi\nret\n"
);
static void *allocate(unsigned size) {void *p=HeapAlloc(fixture_heap,0,size);CHECK(p!=NULL);return p;}
static uint32_t random_word(uint32_t *s) {*s^=*s<<13;*s^=*s>>17;*s^=*s<<5;return *s;}
static void make_source(unsigned char *p,uint32_t seed) {
    for(unsigned i=0;i<0x278;i++)p[i]=(unsigned char)random_word(&seed);
    WORD(p,0)=ptr(image_va(0xe36428));p[0x10]=0;
    WORD(p,0x24)=WORD(p,0x23c)=0;WORD(p,0x28)=WORD(p,0x240)=15;
    p[0x14]=p[0x22c]=0;
    WORD(p,0x3c)=WORD(p,0x40)=WORD(p,0x44)=0;
    WORD(p,0x1d4)=WORD(p,0x220)=0;
    for(unsigned i=0;i<4;i++) {
        unsigned off=0x74+i*0x28;
        WORD(p,off)=ptr(image_va(0xdfd2cc));
        for(unsigned j=0;j<3;j++)WORD(p,off+8+j*4)=WORD(p,off+24+j*4)=0;
    }
}
static void copy_model(unsigned char *d,const unsigned char *s) {
    static const unsigned copies[]={0x58,0x5c,0x60,0x64,0x68,0x6c,0x70,
        0x118,0x11c,0x120,0x124,0x128,0x12c,0x130,0x134,0x138,0x13c,0x140,0x144,
        0x150,0x154,0x180,0x184,0x1c8,0x1cc,0x268,0x270,0x274};
    static const unsigned zeroes[]={0x30,0x34,0x3c,0x40,0x44,0x50,0x54,0x148,0x14c,
        0x158,0x15c,0x160,0x164,0x168,0x16c,0x170,0x174,0x178,
        0x188,0x18c,0x190,0x194,0x198,0x19c,0x1a0,0x1a4,0x1a8,
        0x1b0,0x1b4,0x1b8,0x1bc,0x1c0,0x1c4,
        0x1d4,0x1d8,0x1dc,0x1e0,0x1e4,0x1e8,0x1ec,0x1f0,0x1f4,0x1f8,0x1fc,
        0x200,0x204,0x208,0x20c,0x210,0x214,0x218,0x21c,0x220,
        0x248,0x24c,0x250,0x254,0x258,0x260,0x264,0x26c};
    WORD(d,0)=ptr(image_va(0xe36428));WORD(d,4)=0x18d;
    WORD(d,8)=0x76543210;WORD(d,12)=0xfedcba98;
    d[0x10]=d[0x14]=d[0x38]=0;WORD(d,0x24)=0;WORD(d,0x28)=15;d[0x4c]=s[0x4c];
    for(unsigned i=0;i<sizeof copies/sizeof *copies;i++)WORD(d,copies[i])=WORD(s,copies[i]);
    for(unsigned i=0;i<sizeof zeroes/sizeof *zeroes;i++)WORD(d,zeroes[i])=0;
    for(unsigned i=0;i<4;i++) {
        unsigned off=0x74+i*0x28;
        WORD(d,off)=ptr(image_va(0xdfd2cc));WORD(d,off+4)=WORD(s,off+4);
        for(unsigned j=0;j<3;j++)WORD(d,off+8+j*4)=WORD(d,off+24+j*4)=0;
    }
    WORD(d,0x224)=0x76543210;WORD(d,0x228)=0xfedcba98;
    d[0x22c]=0;WORD(d,0x23c)=0;WORD(d,0x240)=15;
    *(uint16_t *)(d+0x1d0)=0;d[0x1d2]=0;
}
static void destructor_model(unsigned char *p) {
    WORD(p,0)=ptr(image_va(0xe3a544));
    WORD(p,0x220)=0;
    WORD(p,0x23c)=WORD(p,0x24)=0;WORD(p,0x240)=WORD(p,0x28)=15;
    p[0x14]=p[0x22c]=0;
    for(unsigned j=0;j<8;j++)for(unsigned k=0;k<3;k++)WORD(p,vector_offsets[j]+k*4)=0;
}

static void populate(unsigned char *object,unsigned row,unsigned profile) {
    static const unsigned counts[4]={0,1,3,7};
    for(unsigned j=0;j<8;j++) {
        source_buffer *b=&source_buffers[row][j];
        b->logical=profile==5?((j/2)%2?catalog_b_count:catalog_a_count)+source_surplus:
            (profile==4?counts[j%4]:counts[profile]);
        unsigned stride=j%2?4:8;
        b->size=(b->logical+2)*stride;b->p=allocate(b->size);
        for(unsigned k=0;k<b->size;k++)b->before[k]=(unsigned char)(row*19+j*31+k*7);
        memcpy(b->p,b->before,b->size);
        WORD(object,vector_offsets[j])=ptr(b->p);
        WORD(object,vector_offsets[j]+4)=ptr(b->p)+b->logical*stride;
        WORD(object,vector_offsets[j]+8)=ptr(b->p)+b->size;
    }
}
static void plan_buffers(unsigned row) {
    for(unsigned j=0;j<8;j++) {
        source_buffer *b=&source_buffers[row][j];
        if(!b->logical)continue;
        CHECK(plan_count<160);
        allocation_plan[plan_count].size=b->logical*(j%2?4:8);
        memcpy(allocation_plan[plan_count].expected,b->before,allocation_plan[plan_count].size);
        if(j%2) {
            unsigned count=(j/2)%2?catalog_b_count:catalog_a_count;
            unsigned field=(j/2)%2?0x30:8;
            unsigned array_offset=(j/2)%2?0x58:0xc;
            CHECK(count<=b->logical);
            uint32_t *entries=(void *)(uintptr_t)WORD(catalog,array_offset);
            for(unsigned k=0;k<count;k++) {
                WORD(allocation_plan[plan_count].expected,k*4)=WORD((void *)(uintptr_t)entries[k],field);
                catalog_words_checked++;
            }
        }
        plan_count++;
    }
}
static void resolve_buffers(unsigned char *expected,unsigned row,unsigned *allocation_index) {
    for(unsigned j=0;j<8;j++) {
        source_buffer *b=&source_buffers[row][j];unsigned off=vector_offsets[j];
        if(!b->logical)continue;
        allocation_item *item=&allocation_plan[(*allocation_index)++];
        WORD(expected,off)=ptr(item->p);WORD(expected,off+4)=WORD(expected,off+8)=ptr(item->p)+item->size;
    }
}
static void run_case(unsigned n,int index,unsigned pattern,unsigned profile) {
    unsigned char external[0x278],external_before[0x278],source_before[0x278];
    unsigned char catalog_before[sizeof catalog];
    unsigned capacity=n ? n+n/2 : 1;
    if(capacity<n+1)capacity=n+1;
    CHECK(n<=16 && index<(int)n);
    old_array=n?allocate(n*0x278):NULL;
    for(unsigned i=0;i<n;i++)make_source(old_array+i*0x278,0xaabb0000+n*100+i+pattern);
    make_source(external,0xccdd1234+n+pattern);
    memset(source_buffers,0,sizeof source_buffers);
    if(profile) {
        for(unsigned i=0;i<n;i++)populate(old_array+i*0x278,i,profile);
        populate(external,16,profile);
    }
    memcpy(external_before,external,sizeof external);
    unsigned char *source=index<0?external:old_array+index*0x278;
    memcpy(source_before,source,sizeof source_before);
    unsigned char *expected=allocate(capacity*0x278);
    memset(expected,pattern,capacity*0x278);
    for(unsigned i=0;i<n;i++)copy_model(expected+i*0x278,old_array+i*0x278);
    copy_model(expected+n*0x278,source_before);
    expected_bytes=n*0x278;
    if(n)memcpy(expected_old,old_array,expected_bytes);
    for(unsigned i=0;i<n;i++)destructor_model(expected_old+i*0x278);
    uint32_t header[3]={ptr(old_array),ptr(old_array)+n*0x278,ptr(old_array)+n*0x278};
    current_header=header;memcpy(old_header,header,sizeof header);
    call_allocs=call_frees=0;allocation_bytes=capacity*0x278;allocation_pattern=pattern;new_array=NULL;
    memset(allocation_plan,0,sizeof allocation_plan);allocation_plan[0].size=allocation_bytes;plan_count=1;free_plan_count=0;
    if(profile) {
        for(unsigned i=0;i<n;i++)plan_buffers(i);
        plan_buffers(index<0?16:(unsigned)index);
        for(unsigned i=0;i<n;i++)for(unsigned j=8;j>0;j--)free_plan[free_plan_count++]=&source_buffers[i][j-1];
    }
    WORD(private_image,0xf20c04-0x400000)=0x11111111;
    WORD(private_image,0xf20c08-0x400000)=0x22222222;
    memcpy(catalog_before,catalog,sizeof catalog);
    uint32_t before_fs,after_fs;
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(before_fs));
    void *result=invoke_append(header,source,image_va(0x4beb50));
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(after_fs));
    CHECK(before_fs==after_fs);
    CHECK(call_allocs==plan_count && call_frees==free_plan_count+(n?1u:0u));
    CHECK(header[0]==ptr(new_array) && header[1]==ptr(new_array)+(n+1)*0x278 && header[2]==ptr(new_array)+capacity*0x278);
    CHECK(result==(unsigned char *)new_array+n*0x278);
    if(profile) {
        unsigned at=1;
        for(unsigned i=0;i<n;i++)resolve_buffers(expected+i*0x278,i,&at);
        resolve_buffers(expected+n*0x278,index<0?16:(unsigned)index,&at);CHECK(at==plan_count);
        for(unsigned i=1;i<plan_count;i++) {
            CHECK(memcmp(allocation_plan[i].p,allocation_plan[i].expected,allocation_plan[i].size)==0);
            for(unsigned j=0;j<i;j++)CHECK(allocation_plan[i].p!=allocation_plan[j].p);
            for(unsigned j=0;j<8;j++)CHECK(allocation_plan[i].p!=source_buffers[16][j].p);
        }
        for(unsigned j=0;j<8;j++) {
            source_buffer *b=&source_buffers[16][j];CHECK(memcmp(b->p,b->before,b->size)==0);
        }
    }
    CHECK(memcmp(new_array,expected,capacity*0x278)==0);
    CHECK(memcmp(external,external_before,sizeof external)==0);
    CHECK(memcmp(catalog,catalog_before,sizeof catalog)==0);
    CHECK(WORD(private_image,0xf20c04-0x400000)==ptr(catalog+0x100));
    CHECK(WORD(private_image,0xf20c08-0x400000)==ptr(catalog+0x200));
    for(unsigned i=1;i<plan_count;i++)CHECK(HeapFree(fixture_heap,0,allocation_plan[i].p));
    if(profile)for(unsigned j=0;j<8;j++)CHECK(HeapFree(fixture_heap,0,source_buffers[16][j].p));
    CHECK(HeapFree(fixture_heap,0,new_array));CHECK(HeapFree(fixture_heap,0,expected));
    printf("{\"kind\":\"case\",\"old_count\":%u,\"source_index\":%d,\"pattern\":%u,\"distribution_profile\":%u,\"catalog_a_count\":%u,\"catalog_b_count\":%u,\"source_surplus\":%u,\"new_capacity\":%u,\"original_heap_allocs\":%u,\"original_heap_frees\":%u}\n",n,index,pattern,profile,catalog_a_count,catalog_b_count,source_surplus,capacity,call_allocs,call_frees);
    cases++;
}
static void prepare_catalogs(unsigned a,unsigned b,unsigned surplus) {
    CHECK(a<=7 && b<=7 && surplus<=2);
    memset(catalog,0,sizeof catalog);catalog_a_count=a;catalog_b_count=b;source_surplus=surplus;
    WORD(catalog,0xc)=ptr(catalog+0x300);WORD(catalog,0x10)=ptr(catalog+0x300)+4*a;
    WORD(catalog,0x58)=ptr(catalog+0x340);WORD(catalog,0x5c)=ptr(catalog+0x340)+4*b;
    for(unsigned i=0;i<a;i++) {
        WORD(catalog,0x300+i*4)=ptr(catalog+0x400+i*0x40);
        WORD(catalog,0x400+i*0x40+8)=0xabc00000+i*19+a;
    }
    for(unsigned i=0;i<b;i++) {
        WORD(catalog,0x340+i*4)=ptr(catalog+0x800+i*0x40);
        WORD(catalog,0x800+i*0x40+0x30)=0xdef00000+i*23+b;
    }
}
static void optional_model(unsigned char *d,void *first,void *second) {
    for(unsigned i=0;i<2;i++) {
        unsigned off=i*0x58;void *buffer=i?second:first;
        WORD(d,off)=ptr(image_va(0xdfbddc));WORD(d,off+4)=0x18d;
        memset(d+off+8,0,64);
        WORD(d,off+0x48)=ptr(buffer);WORD(d,off+0x4c)=WORD(d,off+0x50)=ptr(buffer)+8;
    }
    static const unsigned zeroes[]={0xb0,0xb8,0xbc,0xc0,0xc4,0xcc,0xd4,0xdc,0xe0,0xe4,0xec,0xf0,0xf4,0xf8,0xfc};
    for(unsigned j=0;j<sizeof zeroes/sizeof *zeroes;j++)WORD(d,zeroes[j])=0;
    WORD(d,0xc8)=WORD(d,0xd0)=WORD(d,0xd8)=0x8000;WORD(d,0xe8)=16384;
}
static void run_constructor_case(unsigned a,unsigned b,unsigned pattern,unsigned cache_mode,unsigned optional) {
    unsigned char object[0x278],expected[0x278],template[0x278]={0};
    unsigned char catalog_before[sizeof catalog];
    unsigned char saved_fx[512] __attribute__((aligned(16)));
    uint32_t dummy_header[3]={0};
    prepare_catalogs(a,b,0);memset(object,pattern,sizeof object);memset(expected,pattern,sizeof expected);
    catalog[0xc00+0x39c]=(unsigned char)optional;
    WORD(template,0x68)=ptr(catalog+0xc00);
    WORD(template,0x6c)=ptr(catalog+0xa00);WORD(template,0x70)=ptr(catalog+0xb00);
    WORD(template,0x130)=WORD(template,0x138)=0x8000;WORD(template,0x128)=3277;
    for(unsigned i=0;i<4;i++)WORD(template,0x74+i*0x28+4)=0x18d;
    copy_model(expected,template);
    memset(source_buffers,0,sizeof source_buffers);memset(allocation_plan,0,sizeof allocation_plan);
    plan_count=free_plan_count=call_allocs=call_frees=0;old_array=NULL;new_array=NULL;
    allocation_pattern=pattern;current_header=dummy_header;memset(old_header,0,sizeof old_header);
    for(unsigned j=0;j<8;j++) {
        source_buffer *sb=&source_buffers[0][j];sb->logical=(j/2)%2?b:a;sb->size=sb->logical*(j%2?4:8);
        if(!sb->logical)continue;
        allocation_plan[plan_count].size=sb->size;
        if(j%2) {
            unsigned array_offset=(j/2)%2?0x58:0xc,field=(j/2)%2?0x30:8;
            uint32_t *entries=(void *)(uintptr_t)WORD(catalog,array_offset);
            for(unsigned k=0;k<sb->logical;k++) {
                WORD(allocation_plan[plan_count].expected,k*4)=WORD((void *)(uintptr_t)entries[k],field);
                catalog_words_checked++;
            }
        }
        plan_count++;
    }
    unsigned optional_index=plan_count;
    if(optional) {
        allocation_plan[plan_count++].size=256;
        for(unsigned i=0;i<2;i++) {
            allocation_plan[plan_count].size=8;
            WORD(allocation_plan[plan_count].expected,0)=pattern==0?0:(pattern==255?0xffffffff:0x89abcdef);
            WORD(allocation_plan[plan_count].expected,4)=pattern==0?0:(pattern==255?0xffffffff:0x01234567);
            plan_count++;
        }
        WORD(private_image,0x125e448-0x400000)=WORD(allocation_plan[optional_index+1].expected,0);
        WORD(private_image,0x125e44c-0x400000)=WORD(allocation_plan[optional_index+1].expected,4);
    }
    WORD(private_image,0x12587ec-0x400000)=ptr(catalog+0xa00);
    WORD(private_image,0x125880c-0x400000)=ptr(catalog+0xb00);
    WORD(private_image,0xf20c04-0x400000)=cache_mode&1?0:0x11111111;
    WORD(private_image,0xf20c08-0x400000)=cache_mode&2?0:0x22222222;
    memcpy(catalog_before,catalog,sizeof catalog);
    uint32_t before_fs,after_fs;uint16_t cw,sw;
    __asm__ __volatile__("fxsave %0\nfninit":"=m"(saved_fx));
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(before_fs));
    void *result=invoke_construct(object,catalog+0xc00,image_va(0x954f40));
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(after_fs));
    __asm__ __volatile__("fnstcw %0\nfnstsw %1":"=m"(cw),"=m"(sw));
    CHECK(result==object && before_fs==after_fs && cw==0x37f && (sw&0x3800)==0);
    CHECK(call_allocs==plan_count && call_frees==0);
    unsigned at=0;
    for(unsigned j=0;j<8;j++) {
        source_buffer *sb=&source_buffers[0][j];if(!sb->logical)continue;
        allocation_item *item=&allocation_plan[at++];sb->p=item->p;
        CHECK(memcmp(sb->p,item->expected,sb->size)==0);memcpy(sb->before,item->expected,sb->size);
        for(unsigned k=0;k<at-1;k++)CHECK(sb->p!=allocation_plan[k].p);
        WORD(expected,vector_offsets[j])=ptr(sb->p);
        WORD(expected,vector_offsets[j]+4)=WORD(expected,vector_offsets[j]+8)=ptr(sb->p)+sb->size;
    }
    CHECK(at==optional_index);
    if(optional) {
        void *resource=allocation_plan[at].p,*first=allocation_plan[at+1].p,*second=allocation_plan[at+2].p;
        unsigned char optional_expected[256];memset(optional_expected,pattern,sizeof optional_expected);
        optional_model(optional_expected,first,second);
        CHECK(memcmp(resource,optional_expected,sizeof optional_expected)==0);
        WORD(expected,0x1d4)=ptr(resource);
        for(unsigned i=1;i<=2;i++) {
            CHECK(memcmp(allocation_plan[at+i].p,allocation_plan[at+i].expected,8)==0);
            source_buffers[1][i].p=allocation_plan[at+i].p;source_buffers[1][i].size=8;
            memcpy(source_buffers[1][i].before,allocation_plan[at+i].expected,8);
        }
        for(unsigned i=0;i<plan_count;i++)for(unsigned j=0;j<i;j++)CHECK(allocation_plan[i].p!=allocation_plan[j].p);
        for(unsigned i=0;i<3;i++)WORD(optional_expected,0x48+4*i)=WORD(optional_expected,0xa0+4*i)=0;
        source_buffers[1][0].p=resource;source_buffers[1][0].size=256;
        memcpy(source_buffers[1][0].before,optional_expected,sizeof optional_expected);
        free_plan[free_plan_count++]=&source_buffers[1][2];
        free_plan[free_plan_count++]=&source_buffers[1][1];
        free_plan[free_plan_count++]=&source_buffers[1][0];
    }
    CHECK(memcmp(object,expected,sizeof object)==0);
    CHECK(WORD(private_image,0xf20c04-0x400000)==(cache_mode&1?ptr(catalog+0x100):0x11111111));
    CHECK(WORD(private_image,0xf20c08-0x400000)==(cache_mode&2?ptr(catalog+0x200):0x22222222));
    for(unsigned j=8;j>0;j--)if(source_buffers[0][j-1].logical)free_plan[free_plan_count++]=&source_buffers[0][j-1];
    ((void (__stdcall *)(void *))image_va(0x955ae0))(object);
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(after_fs));
    __asm__ __volatile__("fxrstor %0"::"m"(saved_fx));
    CHECK(after_fs==before_fs && call_frees==plan_count);
    destructor_model(expected);CHECK(memcmp(object,expected,sizeof object)==0);
    CHECK(memcmp(catalog,catalog_before,sizeof catalog)==0);
    if(optional) {
        CHECK(WORD(private_image,0x125e448-0x400000)==WORD(allocation_plan[optional_index+1].expected,0));
        CHECK(WORD(private_image,0x125e44c-0x400000)==WORD(allocation_plan[optional_index+1].expected,4));
    }
    printf("{\"kind\":\"case\",\"entry\":\"constructor_lifecycle\",\"pattern\":%u,\"catalog_a_count\":%u,\"catalog_b_count\":%u,\"cache_mode\":%u,\"optional_enabled\":%u,\"original_heap_allocs\":%u,\"original_heap_frees\":%u}\n",pattern,a,b,cache_mode,optional,call_allocs,call_frees);
    cases++;
}
static void run_pool_copy_case(unsigned n,unsigned m,unsigned cap,unsigned map_bytes,unsigned pattern) {
    unsigned char src[0x58],dst[0x58],src_before[0x58],expected[0x58];
    unsigned char source_values[256],destination_values[256],expected_values[256];
    uint32_t seed=0x47dbb0+n*100+m*10+map_bytes;
    CHECK(n<=16 && m<=cap && cap<=18 && map_bytes<=64);
    for(unsigned i=0;i<sizeof src;i++) {src[i]=(unsigned char)random_word(&seed);dst[i]=(unsigned char)random_word(&seed);}
    unsigned char *sb=n?allocate((n+2)*8):NULL,*db=cap?allocate(cap*8):NULL;
    for(unsigned i=0;i<(n+2)*8;i++)source_values[i]=(unsigned char)random_word(&seed);
    for(unsigned i=0;i<cap*8;i++)destination_values[i]=(unsigned char)(pattern+i*17);
    if(sb)memcpy(sb,source_values,(n+2)*8);
    if(db)memcpy(db,destination_values,cap*8);
    WORD(src,0)=WORD(dst,0)=ptr(image_va(0xdfbddc));WORD(src,4)=WORD(dst,4)=0x18d;
    WORD(src,0x48)=ptr(sb);WORD(src,0x4c)=ptr(sb)+n*8;WORD(src,0x50)=ptr(sb)+(sb?(n+2)*8:0);
    WORD(dst,0x48)=ptr(db);WORD(dst,0x4c)=ptr(db)+m*8;WORD(dst,0x50)=ptr(db)+cap*8;
    memcpy(src_before,src,sizeof src);memcpy(expected,dst,sizeof dst);
    memcpy(expected+8,src+8,map_bytes);
    unsigned grows=n>cap,new_capacity=grows?(cap+cap/2>n?cap+cap/2:n):cap;
    if(grows) {
        memset(expected_values,pattern,new_capacity*8);
        if(m)memcpy(expected_values,destination_values,m*8);
    } else if(cap)memcpy(expected_values,destination_values,cap*8);
    if(n>m)memset(expected_values+m*8,0,(n-m)*8);
    if(n>1)memcpy(expected_values+8,source_values+8,(n-1)*8);
    old_array=NULL;new_array=NULL;allocation_pattern=pattern;call_allocs=call_frees=0;
    plan_count=grows?1:0;free_plan_count=0;memset(allocation_plan,0,sizeof allocation_plan);
    if(grows)allocation_plan[0].size=new_capacity*8;
    current_header=(uint32_t *)(dst+0x48);memcpy(old_header,current_header,sizeof old_header);
    if(grows && db) {
        source_buffers[0][0].p=db;source_buffers[0][0].size=cap*8;
        memcpy(source_buffers[0][0].before,destination_values,cap*8);
        free_plan[free_plan_count++]=&source_buffers[0][0];
    }
    WORD(private_image,0x12587f4-0x400000)=map_bytes;
    uint32_t before_fs,after_fs;
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(before_fs));
    void *result=((void *(__stdcall *)(void *,void *))image_va(0x47dbb0))(dst,src);
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(after_fs));
    void *result_buffer=grows?new_array:db;
    WORD(expected,0x48)=ptr(result_buffer);WORD(expected,0x4c)=ptr(result_buffer)+n*8;WORD(expected,0x50)=ptr(result_buffer)+new_capacity*8;
    CHECK(result==dst && before_fs==after_fs && call_allocs==grows && call_frees==(grows&&db?1u:0u));
    CHECK(memcmp(dst,expected,sizeof dst)==0 && memcmp(src,src_before,sizeof src)==0);
    if(new_capacity)CHECK(memcmp(result_buffer,expected_values,new_capacity*8)==0);
    if(sb) {
        CHECK(result_buffer!=sb && memcmp(sb,source_values,(n+2)*8)==0);
        CHECK(HeapFree(fixture_heap,0,sb));
    }
    if(result_buffer)CHECK(HeapFree(fixture_heap,0,result_buffer));
    CHECK(WORD(private_image,0x12587f4-0x400000)==map_bytes);
    printf("{\"kind\":\"case\",\"entry\":\"goods_pool_copy\",\"source_count\":%u,\"old_destination_count\":%u,\"old_capacity\":%u,\"map_bytes\":%u,\"pattern\":%u,\"new_capacity\":%u,\"original_heap_allocs\":%u,\"original_heap_frees\":%u}\n",n,m,cap,map_bytes,pattern,new_capacity,call_allocs,call_frees);
    cases++;
}
static void run_optional_copy_case(unsigned n,unsigned second_n,unsigned map_bytes,unsigned pattern,unsigned a,unsigned b,unsigned surplus) {
    unsigned char src[0x278],dst[0x278],src_before[0x278],expected[0x278];
    unsigned char source_resource[256],resource_before[256],resource_expected[256];
    unsigned char first_values[160],second_values[80],first_expected[256];
    unsigned char saved_fx[512] __attribute__((aligned(16)));
    unsigned char catalog_before[sizeof catalog];
    uint32_t dummy_header[3]={0},seed=0x955450+n*100+second_n*10+map_bytes;
    CHECK(n<=16 && second_n>=1 && second_n<=7 && map_bytes<=64);
    unsigned combined=a||b||surplus;
    prepare_catalogs(a,b,surplus);make_source(src,seed);memset(dst,pattern,sizeof dst);memset(expected,pattern,sizeof expected);
    memset(source_buffers,0,sizeof source_buffers);
    if(combined)populate(src,16,5);
    for(unsigned i=0;i<256;i++)source_resource[i]=(unsigned char)random_word(&seed);
    for(unsigned i=0;i<(n+2)*8;i++)first_values[i]=(unsigned char)random_word(&seed);
    for(unsigned i=0;i<(second_n+2)*8;i++)second_values[i]=(unsigned char)random_word(&seed);
    void *source_first=allocate((n+2)*8),*source_second=allocate((second_n+2)*8);
    memcpy(source_first,first_values,(n+2)*8);memcpy(source_second,second_values,(second_n+2)*8);
    WORD(source_resource,0)=WORD(source_resource,0x58)=ptr(image_va(0xdfbddc));
    WORD(source_resource,4)=WORD(source_resource,0x5c)=0x18d;
    WORD(source_resource,0x48)=ptr(source_first);WORD(source_resource,0x4c)=ptr(source_first)+n*8;WORD(source_resource,0x50)=ptr(source_first)+(n+2)*8;
    WORD(source_resource,0xa0)=ptr(source_second);WORD(source_resource,0xa4)=ptr(source_second)+second_n*8;WORD(source_resource,0xa8)=ptr(source_second)+(second_n+2)*8;
    WORD(src,0x1d4)=ptr(source_resource);memcpy(src_before,src,sizeof src);memcpy(resource_before,source_resource,256);
    copy_model(expected,src);
    memset(allocation_plan,0,sizeof allocation_plan);plan_count=0;
    if(combined)plan_buffers(16);
    copy_optional_index=plan_count;unsigned oi=copy_optional_index;
    allocation_plan[oi].size=256;allocation_plan[oi+1].size=allocation_plan[oi+2].size=8;
    for(unsigned j=oi+1;j<=oi+2;j++) {
        WORD(allocation_plan[j].expected,0)=pattern==0?0:(pattern==255?0xffffffff:0x89abcdef);
        WORD(allocation_plan[j].expected,4)=pattern==0?0:(pattern==255?0xffffffff:0x01234567);
    }
    plan_count=oi+(n>1?4:3);if(n>1)allocation_plan[oi+3].size=n*8;
    call_allocs=call_frees=free_plan_count=0;old_array=NULL;new_array=NULL;allocation_pattern=pattern;
    current_header=dummy_header;memset(old_header,0,sizeof old_header);copy_intermediate_free=n>1;
    WORD(private_image,0x12587f4-0x400000)=map_bytes;
    WORD(private_image,0x125e448-0x400000)=WORD(allocation_plan[oi+1].expected,0);
    WORD(private_image,0x125e44c-0x400000)=WORD(allocation_plan[oi+1].expected,4);
    memcpy(catalog_before,catalog,sizeof catalog);
    uint32_t before_fs,after_fs;
    __asm__ __volatile__("fxsave %0\nfninit":"=m"(saved_fx));
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(before_fs));
    void *result=((void *(__stdcall *)(void *,void *))image_va(0x955450))(dst,src);
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(after_fs));
    CHECK(result==dst && after_fs==before_fs && call_allocs==plan_count && call_frees==(n>1?1u:0u) && copy_intermediate_free==0);
    unsigned copy_frees=call_frees;call_frees=0;
    if(combined) {
        unsigned at=0;resolve_buffers(expected,16,&at);CHECK(at==oi);at=0;
        for(unsigned j=0;j<8;j++) {
            source_buffer *original=&source_buffers[16][j],*copy=&source_buffers[0][j];
            if(!original->logical)continue;
            allocation_item *item=&allocation_plan[at++];CHECK(memcmp(item->p,item->expected,item->size)==0);
            copy->p=item->p;copy->logical=original->logical;copy->size=item->size;memcpy(copy->before,item->expected,item->size);
            CHECK(copy->p!=original->p);
        }
    }
    void *resource=allocation_plan[oi].p,*first=n>1?allocation_plan[oi+3].p:allocation_plan[oi+1].p,*second=allocation_plan[oi+2].p;
    WORD(expected,0x1d4)=ptr(resource);CHECK(memcmp(dst,expected,sizeof dst)==0);
    memset(resource_expected,pattern,256);optional_model(resource_expected,first,second);
    WORD(resource_expected,0x4c)=ptr(first)+n*8;WORD(resource_expected,0x50)=ptr(first)+(n>1?n:1)*8;
    memcpy(resource_expected+8,source_resource+8,map_bytes);
    CHECK(memcmp(resource,resource_expected,256)==0);
    unsigned first_bytes=(n>1?n:1)*8;
    memcpy(first_expected,allocation_plan[oi+1].expected,8);
    if(n>1)memcpy(first_expected+8,first_values+8,(n-1)*8);
    CHECK(memcmp(first,first_expected,first_bytes)==0);
    CHECK(memcmp(second,allocation_plan[oi+2].expected,8)==0);
    source_buffers[1][1].p=first;source_buffers[1][1].size=first_bytes;memcpy(source_buffers[1][1].before,first_expected,first_bytes);
    source_buffers[1][2].p=second;source_buffers[1][2].size=8;memcpy(source_buffers[1][2].before,allocation_plan[oi+2].expected,8);
    for(unsigned j=0;j<3;j++)WORD(resource_expected,0x48+j*4)=WORD(resource_expected,0xa0+j*4)=0;
    source_buffers[1][0].p=resource;source_buffers[1][0].size=256;memcpy(source_buffers[1][0].before,resource_expected,256);
    free_plan[free_plan_count++]=&source_buffers[1][2];free_plan[free_plan_count++]=&source_buffers[1][1];free_plan[free_plan_count++]=&source_buffers[1][0];
    if(combined)for(unsigned j=8;j>0;j--)if(source_buffers[0][j-1].logical)free_plan[free_plan_count++]=&source_buffers[0][j-1];
    ((void (__stdcall *)(void *))image_va(0x955ae0))(dst);
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(after_fs));
    __asm__ __volatile__("fxrstor %0"::"m"(saved_fx));
    CHECK(after_fs==before_fs && call_frees==3+oi);
    destructor_model(expected);CHECK(memcmp(dst,expected,sizeof dst)==0);
    CHECK(memcmp(src,src_before,sizeof src)==0 && memcmp(source_resource,resource_before,256)==0);
    CHECK(memcmp(source_first,first_values,(n+2)*8)==0 && memcmp(source_second,second_values,(second_n+2)*8)==0);
    CHECK(memcmp(catalog,catalog_before,sizeof catalog)==0);
    if(combined)for(unsigned j=0;j<8;j++) {
        source_buffer *original=&source_buffers[16][j];CHECK(memcmp(original->p,original->before,original->size)==0);
        CHECK(HeapFree(fixture_heap,0,original->p));
    }
    CHECK(HeapFree(fixture_heap,0,source_first));CHECK(HeapFree(fixture_heap,0,source_second));
    printf("{\"kind\":\"case\",\"entry\":\"%s\",\"first_pool_count\":%u,\"second_pool_count\":%u,\"map_bytes\":%u,\"pattern\":%u,\"catalog_a_count\":%u,\"catalog_b_count\":%u,\"source_surplus\":%u,\"original_heap_allocs\":%u,\"original_heap_frees\":%u}\n",combined?"cpop_optional_copy_combined":"cpop_optional_copy",n,second_n,map_bytes,pattern,a,b,surplus,call_allocs,call_frees+copy_frees);
    cases++;
}
static void registered_source(unsigned char *p,uint32_t seed) {
    make_source(p,seed);WORD(p,4)=0x18d;
    WORD(p,8)=0x76543210;WORD(p,12)=0xfedcba98;
    WORD(p,0x58)=WORD(p,0x5c)=WORD(p,0x60)=17;WORD(p,0x64)=0;WORD(p,0x68)=ptr(catalog+0xc00);
    WORD(p,0x220)=0;WORD(p,0x224)=0x76543210;WORD(p,0x228)=0xfedcba98;
}
static void check_registered_tables(uint32_t tables[2][3],uint32_t heads[2][7],unsigned selected,unsigned bucket,unsigned count,void *link,unsigned buckets) {
    for(unsigned t=0;t<2;t++) {
        CHECK(tables[t][0]==(t==selected?count:0) && tables[t][1]==buckets && tables[t][2]==ptr(heads[t]));
        for(unsigned b=0;b<buckets;b++)CHECK(heads[t][b]==(t==selected && b==bucket?ptr(link):0));
    }
}
static void run_registered_copy_case(unsigned kind,unsigned id,unsigned buckets,unsigned pattern,unsigned grow) {
    unsigned char stack_source[0x278],external[0x278],destination[0x278],source_before[0x278],expected[2*0x278];
    uint32_t heads[2][7]={{0}},tables[2][3]={{0}},dummy_header[3]={0};
    CHECK(buckets>0 && buckets<=7);
    prepare_catalogs(0,0,0);unsigned char *source=grow?allocate(0x278):stack_source;
    registered_source(source,kind+id+pattern+1);registered_source(external,0x55667788+pattern);
    for(unsigned t=0;t<2;t++) {tables[t][1]=buckets;tables[t][2]=ptr(heads[t]);WORD(private_image,(t?0x1258a98:0x1258a94)-0x400000)=ptr(tables[t]);}
    memset(allocation_plan,0,sizeof allocation_plan);allocation_plan[0].size=8;
    allocation_pattern=pattern;call_allocs=call_frees=free_plan_count=0;plan_count=1;old_array=NULL;copy_intermediate_free=0;
    current_header=dummy_header;memset(old_header,0,sizeof old_header);registered_link_expected=NULL;
    uint32_t key[2]={kind,id},before_fs,after_fs;
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(before_fs));
    invoke_register(source,key,image_va(0x9c1390));
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(after_fs));
    CHECK(before_fs==after_fs && call_allocs==1 && call_frees==0);
    void *link=allocation_plan[0].p;unsigned selected=kind<=0x1268?1:0,bucket=((kind<<16)+id)%buckets;
    CHECK(WORD(link,0)==ptr(source) && WORD(link,4)==0 && WORD(source,8)==kind && WORD(source,12)==id && source[0x10]==1);
    check_registered_tables(tables,heads,selected,bucket,1,link,buckets);
    uint32_t handle[3]={0xdeadbeef,kind,id};
    CHECK(invoke_refresh(handle,image_va(0x967f50))==source && handle[0]==ptr(source));
    memcpy(source_before,source,sizeof source_before);
    memset(source_buffers,0,sizeof source_buffers);memset(allocation_plan,0,sizeof allocation_plan);
    source_buffers[0][0].p=link;source_buffers[0][0].size=8;memcpy(source_buffers[0][0].before,link,8);
    free_plan[0]=&source_buffers[0][0];free_plan_count=0;call_allocs=call_frees=0;plan_count=grow?1:0;
    registered_link_expected=link;registered_table_expected=tables[selected];registered_heads_expected=heads[selected];registered_bucket_expected=bucket;
    unsigned phase_allocs=0;
    if(grow) {
        uint32_t header[3]={ptr(source),ptr(source)+0x278,ptr(source)+0x278};
        allocation_plan[0].size=2*0x278;old_array=source;expected_bytes=0x278;
        memcpy(expected_old,source_before,0x278);destructor_model(expected_old);WORD(expected_old,8)=id;WORD(expected_old,12)=0xfffe;
        current_header=header;memcpy(old_header,header,sizeof old_header);free_plan_count=1;
        memset(expected,pattern,sizeof expected);copy_model(expected,source_before);copy_model(expected+0x278,external);
        void *result=invoke_append(header,external,image_va(0x4beb50));
        CHECK(call_allocs==1 && call_frees==2 && header[0]==ptr(new_array) && header[1]==ptr(new_array)+2*0x278 && header[2]==header[1]);
        CHECK(result==(unsigned char *)new_array+0x278 && memcmp(new_array,expected,sizeof expected)==0);
        phase_allocs=call_allocs;
        check_registered_tables(tables,heads,selected,bucket,0,NULL,buckets);
        uint32_t cached[3]={ptr(source),kind,id};
        CHECK(invoke_resolve_no_cache(cached,image_va(0x967f10))==NULL && cached[0]==ptr(source));
        CHECK(invoke_refresh(handle,image_va(0x967f50))==NULL && handle[0]==0);
        ((void (__stdcall *)(void *))image_va(0x955ae0))(new_array);
        ((void (__stdcall *)(void *))image_va(0x955ae0))((unsigned char *)new_array+0x278);
        destructor_model(expected);destructor_model(expected+0x278);CHECK(memcmp(new_array,expected,sizeof expected)==0);
        check_registered_tables(tables,heads,selected,bucket,0,NULL,buckets);
        CHECK(HeapFree(fixture_heap,0,new_array));
    } else {
        memset(destination,pattern,sizeof destination);memset(expected,pattern,0x278);copy_model(expected,source_before);
        void *result=((void *(__stdcall *)(void *,void *))image_va(0x955450))(destination,source);
        CHECK(result==destination && call_allocs==0 && call_frees==0 && memcmp(destination,expected,0x278)==0);
        CHECK(invoke_refresh(handle,image_va(0x967f50))==source && handle[0]==ptr(source));
        check_registered_tables(tables,heads,selected,bucket,1,link,buckets);
        ((void (__stdcall *)(void *))image_va(0x955ae0))(destination);
        destructor_model(expected);CHECK(memcmp(destination,expected,0x278)==0 && memcmp(source,source_before,0x278)==0 && call_frees==0);
        CHECK(invoke_refresh(handle,image_va(0x967f50))==source);
        check_registered_tables(tables,heads,selected,bucket,1,link,buckets);
        free_plan_count=1;
        ((void (__stdcall *)(void *))image_va(0x955ae0))(source);
        memcpy(expected,source_before,0x278);destructor_model(expected);WORD(expected,8)=id;WORD(expected,12)=0xfffe;
        CHECK(call_frees==1 && memcmp(source,expected,0x278)==0);
        CHECK(invoke_refresh(handle,image_va(0x967f50))==NULL && handle[0]==0);
        check_registered_tables(tables,heads,selected,bucket,0,NULL,buckets);
    }
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(after_fs));CHECK(after_fs==before_fs);
    CHECK(registered_link_expected==NULL);
    WORD(private_image,0x1258a94-0x400000)=WORD(private_image,0x1258a98-0x400000)=0;
    printf("{\"kind\":\"case\",\"entry\":\"%s\",\"key_type\":%u,\"key_id\":%u,\"buckets\":%u,\"pattern\":%u,\"original_heap_allocs\":%u,\"original_heap_frees\":%u}\n",grow?"registered_vector_growth":"registered_copy_lifecycle",kind,id,buckets,pattern,1+phase_allocs,call_frees);
    cases++;
}
typedef struct {
    unsigned size,slot,other_region;uint64_t balance;
    unsigned merge,destination_size;uint64_t destination_balance,source_attribute,destination_attribute;
    unsigned selector,special,source_level,selector_count,selector_levels[3],selector_predicates[3],selector_flags[3];
} consumer_options;
static uint64_t load_qword(const void *p) {uint64_t value;memcpy(&value,p,8);return value;}
static void store_qword(void *p,uint64_t value) {memcpy(p,&value,8);}
static void merge_model(unsigned char *d,const consumer_options *c) {
    uint64_t sum=(uint64_t)c->size+c->destination_size;
    uint64_t num=(((uint64_t)c->size<<15)*c->source_attribute)&~UINT64_C(0x7fff);
    num+=(((uint64_t)c->destination_size<<15)*c->destination_attribute)&~UINT64_C(0x7fff);
    uint64_t attribute=num>>63?UINT64_C(0)-((UINT64_C(0)-num)/(sum<<15)):num/(sum<<15);
    store_qword(d+0x128,attribute);
    unsigned size=sum>2000000?2000000:(unsigned)sum;
    WORD(d,0x58)=WORD(d,0x60)=size;WORD(d,0x5c)=c->destination_size?c->destination_size:size;
    WORD(d,0x158+4*(c->other_region?2:1))+=c->size;
    uint64_t balance=c->balance+c->destination_balance;
    if(!(c->destination_balance>>63) && c->balance && !(c->balance>>63) && balance>>63)balance=UINT64_C(0x7fffffffffffffff);
    else if(balance>>63)balance=0;
    store_qword(d+0x180,balance);
    store_qword(d+0x1e8,load_qword(d+0x1e8)+c->balance);
    store_qword(d+0x218,load_qword(d+0x218)+c->balance);
}
typedef struct {unsigned province,count,sequence,predicate,fallback_index;} factory_options;
static unsigned char factory_type[0x400];
static void run_factory_case(unsigned type_index,unsigned previous_count,unsigned seed,unsigned bucket_count,unsigned pattern,unsigned a,unsigned b,const consumer_options *consume,const factory_options *internal) {
    unsigned char owner[0x400]={0},template[0x278]={0},expected_node[0x288],saved_fx[512] __attribute__((aligned(16)));
    unsigned char owner_before[0x400],type_before[0x400],catalog_before[sizeof catalog];
    unsigned char selector_types[3][0x400]={{0}},selector_types_before[sizeof selector_types];
    unsigned char *chosen_type=factory_type;int chosen_ordinal=-1;
    unsigned char internal_array[4*0xb0]={0},internal_header[0x110]={0},internal_rows[3][0x20];
    unsigned char internal_array_before[sizeof internal_array],internal_header_before[sizeof internal_header],internal_rows_before[sizeof internal_rows];
    uint32_t internal_singleton[5]={0},internal_singleton_before[5];
    unsigned char previous_before[2][0x288];void *previous[2]={NULL,NULL};
    unsigned char pending[3][0x278],pending_before[sizeof pending],source_owner[0x400]={0},world[0xc20]={0};
    unsigned char outer_head[0x24]={0},outer_node[0x24]={0},inner_head[0x18]={0},inner_node[0x18]={0};
    uint32_t log_header[8]={0},log_header_before[8],log_entry[7]={0},outer_map[3]={0},province_array[1]={0};
    unsigned char world_before[sizeof world],outer_before[sizeof outer_node],inner_before[sizeof inner_node];
    unsigned char outer_head_before[sizeof outer_head],inner_head_before[sizeof inner_head],source_owner_before[sizeof source_owner];
    uint32_t log_entry_before[7],outer_map_before[3];
    uint32_t buckets[3][4]={{0}},expected_buckets[3][4],heads[2][7]={{0}},tables[2][3]={{0}};
    CHECK(type_index<3 && previous_count<=2 && bucket_count>0 && bucket_count<=7);
    unsigned merging=consume && consume->merge;
    prepare_catalogs(a,b,0);memset(factory_type,0,sizeof factory_type);
    WORD(factory_type,0)=ptr(image_va(0xe365f8));WORD(factory_type,0x28)=type_index;
    if(merging)WORD(factory_type,0x30)=0xffffffff;
    WORD(factory_type,0x3d4)=ptr(catalog+0xc00);WORD(catalog,0xc00)=ptr(image_va(0xe36618));
    WORD(owner,0)=ptr(image_va(0xdfd280));WORD(owner,0x12c)=1;WORD(owner,0x194)=ptr(buckets);
    for(unsigned i=0;i<previous_count;i++) {
        previous[i]=allocate(0x288);memset(previous[i],pattern,0x288);registered_source(previous[i],0x11223344+i);
        WORD(previous[i],0x64)=ptr(owner);WORD(previous[i],0x68)=ptr(factory_type);
        if(merging) {
            WORD(previous[i],0x58)=WORD(previous[i],0x60)=consume->destination_size;
            WORD(previous[i],0x6c)=ptr(catalog+0xa00);WORD(previous[i],0x70)=ptr(catalog+0xb00);
            store_qword((unsigned char *)previous[i]+0x128,consume->destination_attribute);
            store_qword((unsigned char *)previous[i]+0x180,consume->destination_balance);
        }
        WORD(previous[i],0x278)=i?ptr(previous[i-1]):0;WORD(previous[i],0x27c)=0;
        if(i)WORD(previous[i-1],0x27c)=ptr(previous[i]);
    }
    for(unsigned i=0;i<previous_count;i++)memcpy(previous_before[i],previous[i],0x288);
    uint32_t *bucket=buckets[type_index];bucket[0]=previous_count?ptr(previous[0]):0;bucket[1]=previous_count?ptr(previous[previous_count-1]):0;bucket[2]=previous_count;
    memcpy(expected_buckets,buckets,sizeof buckets);
    for(unsigned t=0;t<2;t++) {tables[t][1]=bucket_count;tables[t][2]=ptr(heads[t]);WORD(private_image,(t?0x1258a98:0x1258a94)-0x400000)=ptr(tables[t]);}
    WORD(private_image,0x1258a2c-0x400000)=ptr(catalog+0xc00);
    WORD(private_image,0x12587ec-0x400000)=ptr(catalog+0xa00);WORD(private_image,0x125880c-0x400000)=ptr(catalog+0xb00);
    WORD(private_image,0xf20c04-0x400000)=0x11111111;WORD(private_image,0xf20c08-0x400000)=0x22222222;WORD(private_image,0xf20c0c-0x400000)=0x33333333;
    WORD(private_image,0xf09568-0x400000)=seed;unsigned generic_counter=WORD(private_image,0x1258a9c-0x400000);
    memset(allocation_plan,0,sizeof allocation_plan);memset(source_buffers,0,sizeof source_buffers);
    plan_count=0;
    for(unsigned j=0;j<8;j++) {
        unsigned n=(j/2)%2?b:a;if(!n)continue;
        allocation_item *item=&allocation_plan[plan_count++];item->size=n*(j%2?4:8);
        if(j%2) {
            unsigned array_offset=(j/2)%2?0x58:0xc,field=(j/2)%2?0x30:8;
            uint32_t *entries=(void *)(uintptr_t)WORD(catalog,array_offset);
            for(unsigned k=0;k<n;k++) {WORD(item->expected,k*4)=WORD((void *)(uintptr_t)entries[k],field);catalog_words_checked+=2;}
        }
    }
    unsigned active=plan_count,node_index=plan_count;allocation_plan[plan_count++].size=0x288;
    for(unsigned j=0;j<active;j++) {allocation_plan[plan_count]=allocation_plan[j];plan_count++;}
    unsigned link_index=plan_count;allocation_plan[plan_count++].size=8;
    if(merging)plan_count=0;
    factory_temp_remaining=factory_temp_total=active;
    call_allocs=call_frees=free_plan_count=0;old_array=NULL;copy_intermediate_free=0;registered_link_expected=NULL;allocation_pattern=pattern;
    uint32_t dummy_header[3]={0};current_header=dummy_header;memset(old_header,0,sizeof old_header);
    if(consume) {
        CHECK(a==0 && b==0 && previous_count==(merging?1u:0u) && consume->slot<3 && consume->size>0);
        WORD(catalog,0x10c)=ptr(catalog+0x380);WORD(catalog,0x110)=ptr(catalog+0x380)+12;
        for(unsigned i=0;i<3;i++)WORD(catalog,0x380+i*4)=ptr(factory_type);
        if(consume->selector) {
            CHECK(!merging && consume->selector_count<=3);
            WORD(factory_type,0x3c)=consume->source_level;factory_type[0x3d8]=(unsigned char)consume->special;
            WORD(catalog,0x110)=ptr(catalog+0x380)+4*consume->selector_count;
            for(unsigned i=0;i<3;i++) {
                WORD(selector_types[i],0)=ptr(image_va(consume->selector_predicates[i]?0xe365f8:0xe36618));
                WORD(selector_types[i],0x28)=i;WORD(selector_types[i],0x3c)=consume->selector_levels[i];
                WORD(selector_types[i],0x3d4)=ptr(catalog+0xc00);selector_types[i][0x3d9]=(unsigned char)consume->selector_flags[i];
                WORD(catalog,0x380+i*4)=ptr(selector_types[i]);
                if(consume->special && i<consume->selector_count && consume->selector_predicates[i] && !consume->selector_flags[i] && (int32_t)consume->selector_levels[i]<(int32_t)consume->source_level) {
                    chosen_type=selector_types[i];chosen_ordinal=(int)i;
                }
            }
            type_index=WORD(chosen_type,0x28);bucket=buckets[type_index];
            memcpy(selector_types_before,selector_types,sizeof selector_types);
        }
        memset(pending,0,sizeof pending);
        for(unsigned i=0;i<3;i++) {WORD(pending[i],0x58)=i%2?0xffffffff:0;WORD(pending[i],0x5c)=0x12340000+i;WORD(pending[i],0x60)=91+i;WORD(pending[i],0x180)=0x55550000+i;}
        unsigned char *source=pending[consume->slot];memset(source,0,0x278);
        WORD(source,0x58)=consume->size;WORD(source,0x5c)=77;WORD(source,0x60)=88;
        WORD(source,0x64)=ptr(source_owner);WORD(source,0x68)=ptr(factory_type);
        WORD(source,0x6c)=ptr(catalog+0xa00);WORD(source,0x70)=ptr(catalog+0xb00);
        WORD(source,0x78)=WORD(source,0xa0)=0x18d;WORD(source,0x128)=123456;WORD(source,0x12c)=0x789;
        memcpy(source+0x180,&consume->balance,8);
        if(merging)store_qword(source+0x128,consume->source_attribute);
        WORD(source_owner,0x12c)=consume->other_region?0:1;
        WORD(owner,0x30c)=ptr(pending);WORD(owner,0x310)=WORD(owner,0x314)=ptr(pending)+sizeof pending;
        WORD(world,0xc10)=ptr(log_header);WORD(world,0xacc)=ptr(province_array);WORD(world,0xb0c)=0x12345678;
        province_array[0]=ptr(owner);log_header[0]=ptr(log_entry);log_header[1]=ptr(log_entry)+sizeof log_entry;
        log_header[4]=WORD(private_image,0x125a35c-0x400000);
        log_entry[0]=ptr(outer_map);outer_map[1]=ptr(outer_head);outer_map[2]=1;
        WORD(outer_head,4)=ptr(outer_node);outer_head[0x21]=1;
        WORD(outer_node,0)=WORD(outer_node,8)=ptr(outer_head);WORD(outer_node,4)=ptr(outer_head);
        WORD(outer_node,0x14)=ptr(inner_head);WORD(outer_node,0x18)=1;
        WORD(inner_head,4)=ptr(inner_node);inner_head[0x15]=1;
        WORD(inner_node,0)=WORD(inner_node,8)=ptr(inner_head);WORD(inner_node,4)=ptr(inner_head);
        WORD(inner_node,0x10)=0xabcdfff0;
        WORD(private_image,0x12588e8-0x400000)=ptr(world);
        memcpy(outer_head_before,outer_head,sizeof outer_head);memcpy(inner_head_before,inner_head,sizeof inner_head);
        memcpy(source_owner_before,source_owner,sizeof source_owner);memcpy(log_entry_before,log_entry,sizeof log_entry);memcpy(outer_map_before,outer_map,sizeof outer_map);
        memcpy(log_header_before,log_header,sizeof log_header);
        memcpy(pending_before,pending,sizeof pending);memcpy(world_before,world,sizeof world);
        memcpy(outer_before,outer_node,sizeof outer_node);memcpy(inner_before,inner_node,sizeof inner_node);
    }
    if(internal) {
        CHECK(!consume && !previous_count && !a && !b && internal->province<4 && internal->count<=3 && internal->fallback_index>0 && internal->fallback_index<3);
        memset(internal_rows,pattern,sizeof internal_rows);
        WORD(selector_types[0],0)=ptr(image_va(internal->predicate?0xe365f8:0xe36618));
        WORD(selector_types[0],0x28)=internal->fallback_index;WORD(selector_types[1],0)=ptr(image_va(0xe365f8));
        WORD(factory_type,0x3d4)=ptr(selector_types[0]);WORD(owner,0x58)=internal->province;
        internal_singleton[0]=ptr(internal_array);WORD(internal_array,internal->province*0xb0+8)=ptr(internal_header);
        WORD(internal_header,0x108)=ptr(internal_rows);WORD(internal_header,0x10c)=ptr(internal_rows)+internal->count*0x20;
        unsigned code=internal->sequence,found=0;
        for(unsigned i=0;i<internal->count;i++) {
            unsigned value=code%3;code/=3;
            unsigned char *type=value==1?factory_type:value==2?selector_types[0]:selector_types[1];
            WORD(internal_rows[i],8)=ptr(type);
            if(internal->predicate && !found && value) {chosen_type=type;found=1;}
        }
        type_index=WORD(chosen_type,0x28);bucket=buckets[type_index];
        WORD(private_image,0x1258728-0x400000)=ptr(internal_singleton);
        memcpy(selector_types_before,selector_types,sizeof selector_types);
        memcpy(internal_array_before,internal_array,sizeof internal_array);memcpy(internal_header_before,internal_header,sizeof internal_header);
        memcpy(internal_rows_before,internal_rows,sizeof internal_rows);memcpy(internal_singleton_before,internal_singleton,sizeof internal_singleton);
    }
    memcpy(owner_before,owner,sizeof owner);memcpy(type_before,factory_type,sizeof factory_type);memcpy(catalog_before,catalog,sizeof catalog);
    uint32_t before_fs,after_fs;__asm__ __volatile__("fxsave %0\nfninit":"=m"(saved_fx));
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(before_fs));
    void *node;
    if(consume) {
        ((void (__stdcall *)(void *))image_va(0x4ba780))(owner);node=(void *)(uintptr_t)bucket[1];
        unsigned char *source=pending[consume->slot];unsigned char *expected_source=pending_before+consume->slot*0x278;
        WORD(expected_source,0x58)=0;WORD(expected_source,0x5c)=consume->size;WORD(expected_source,0x60)=0;
        WORD(expected_source,0x180)=WORD(expected_source,0x184)=0;
        CHECK(memcmp(pending,pending_before,sizeof pending)==0);
        CHECK(WORD(source,0x68)==ptr(factory_type));
        WORD(owner_before,0x354)=WORD(world,0xb0c);
        WORD(log_header_before,0x10)=WORD(world,0xb0c);
        CHECK(memcmp(log_header,log_header_before,sizeof log_header)==0);
        CHECK(memcmp(world,world_before,sizeof world)==0 && memcmp(outer_node,outer_before,sizeof outer_node)==0);
        unsigned delta=consume->size>65535?65535:consume->size;
        WORD(inner_before,0x10)=(WORD(inner_before,0x10)&0xffff0000)|((WORD(inner_before,0x10)+delta)&0xffff);
        CHECK(memcmp(inner_node,inner_before,sizeof inner_node)==0);
        CHECK(memcmp(outer_head,outer_head_before,sizeof outer_head)==0 && memcmp(inner_head,inner_head_before,sizeof inner_head)==0);
        CHECK(memcmp(source_owner,source_owner_before,sizeof source_owner)==0 && memcmp(log_entry,log_entry_before,sizeof log_entry)==0);
        CHECK(memcmp(outer_map,outer_map_before,sizeof outer_map)==0 && province_array[0]==ptr(owner));
    } else node=((void *(__stdcall *)(void *,void *))image_va(0x4b8d30))(owner,factory_type);
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(after_fs));
    if(merging) {
        CHECK(node==previous[0] && call_allocs==0 && call_frees==0 && before_fs==after_fs);
        CHECK(WORD(private_image,0xf09568-0x400000)==seed && WORD(private_image,0x1258a9c-0x400000)==generic_counter);
        memcpy(expected_node,previous_before[0],sizeof expected_node);merge_model(expected_node,consume);
        if(memcmp(node,expected_node,sizeof expected_node))for(unsigned off=0;off<sizeof expected_node;off+=4)if(WORD(node,off)!=WORD(expected_node,off))fprintf(stderr,"merge node+%x actual=%08x expected=%08x\n",off,WORD(node,off),WORD(expected_node,off));
        CHECK(memcmp(node,expected_node,sizeof expected_node)==0 && memcmp(buckets,expected_buckets,sizeof buckets)==0);
        CHECK(memcmp(owner,owner_before,sizeof owner)==0 && memcmp(factory_type,type_before,sizeof factory_type)==0 && memcmp(catalog,catalog_before,sizeof catalog)==0);
        check_registered_tables(tables,heads,1,0,0,NULL,bucket_count);
        old_array=node;expected_bytes=0x288;memcpy(expected_old,expected_node,sizeof expected_node);destructor_model(expected_old);
        current_header=bucket;old_header[0]=old_header[1]=0;old_header[2]=1;
        CHECK(invoke_unlink(bucket,node,image_va(0x4be8d0))==1);
        __asm__ __volatile__("movl %%fs:0,%0":"=r"(after_fs));__asm__ __volatile__("fxrstor %0"::"m"(saved_fx));
        CHECK(after_fs==before_fs && call_frees==1);
        memset(expected_buckets[type_index],0,3*sizeof(uint32_t));CHECK(memcmp(buckets,expected_buckets,sizeof buckets)==0);
        check_registered_tables(tables,heads,1,0,0,NULL,bucket_count);
        CHECK(memcmp(owner,owner_before,sizeof owner)==0 && memcmp(factory_type,type_before,sizeof factory_type)==0 && memcmp(catalog,catalog_before,sizeof catalog)==0);
        WORD(private_image,0x1258a94-0x400000)=WORD(private_image,0x1258a98-0x400000)=0;
        printf("{\"kind\":\"case\",\"entry\":\"pop_consumer_merge\",\"size\":%u,\"destination_size\":%u,\"slot\":%u,\"other_region\":%u,\"source_balance\":\"%016llx\",\"destination_balance\":\"%016llx\",\"source_attribute\":\"%016llx\",\"destination_attribute\":\"%016llx\",\"result_attribute\":\"%016llx\",\"result_balance\":\"%016llx\",\"type_index\":%u,\"pattern\":%u,\"original_heap_allocs\":%u,\"original_heap_frees\":%u}\n",consume->size,consume->destination_size,consume->slot,consume->other_region,(unsigned long long)consume->balance,(unsigned long long)consume->destination_balance,(unsigned long long)consume->source_attribute,(unsigned long long)consume->destination_attribute,(unsigned long long)load_qword(expected_node+0x128),(unsigned long long)load_qword(expected_node+0x180),type_index,pattern,call_allocs,call_frees);
        cases++;return;
    }
    CHECK(node==allocation_plan[node_index].p && call_allocs==plan_count && call_frees==active && factory_temp_remaining==0 && before_fs==after_fs);
    unsigned temporary_frees=call_frees;call_frees=0;
    CHECK(WORD(private_image,0xf09568-0x400000)==seed+1 && WORD(private_image,0x1258a9c-0x400000)==generic_counter);
    CHECK(WORD(private_image,0xf20c0c-0x400000)==0x33333333);
    WORD(template,0x68)=ptr(catalog+0xc00);WORD(template,0x6c)=ptr(catalog+0xa00);WORD(template,0x70)=ptr(catalog+0xb00);
    WORD(template,0x130)=WORD(template,0x138)=0x8000;WORD(template,0x128)=3277;
    for(unsigned i=0;i<4;i++)WORD(template,0x74+i*0x28+4)=0x18d;
    memset(expected_node,pattern,sizeof expected_node);copy_model(expected_node,template);
    unsigned at=node_index+1;
    for(unsigned j=0;j<8;j++) {
        unsigned n=(j/2)%2?b:a;if(!n)continue;
        allocation_item *item=&allocation_plan[at++];source_buffer *sb=&source_buffers[1][j];
        CHECK(memcmp(item->p,item->expected,item->size)==0);
        sb->p=item->p;sb->size=item->size;memcpy(sb->before,item->expected,item->size);
        WORD(expected_node,vector_offsets[j])=ptr(item->p);
        WORD(expected_node,vector_offsets[j]+4)=WORD(expected_node,vector_offsets[j]+8)=ptr(item->p)+item->size;
    }
    CHECK(at==link_index);
    WORD(expected_node,8)=0x2e;WORD(expected_node,12)=seed;expected_node[0x10]=1;
    WORD(expected_node,0x64)=ptr(owner);WORD(expected_node,0x68)=ptr(chosen_type);
    WORD(expected_node,0x278)=previous_count?ptr(previous[previous_count-1]):0;WORD(expected_node,0x27c)=0;expected_node[0x280]=0;
    if(consume) {
        unsigned size=consume->size>2000000?2000000:consume->size;
        WORD(expected_node,0x58)=WORD(expected_node,0x5c)=WORD(expected_node,0x60)=size;
        WORD(expected_node,0x128)=123456;WORD(expected_node,0x12c)=0x789;
        WORD(expected_node,0x158+4*(consume->other_region?2:1))=consume->size;
        uint64_t balance=(int64_t)consume->balance<0?0:consume->balance;
        memcpy(expected_node+0x180,&balance,8);
    }
    if(memcmp(node,expected_node,sizeof expected_node))for(unsigned off=0;off<sizeof expected_node;off+=4)if(WORD(node,off)!=WORD(expected_node,off))fprintf(stderr,"node+%x actual=%08x expected=%08x\n",off,WORD(node,off),WORD(expected_node,off));
    CHECK(memcmp(node,expected_node,sizeof expected_node)==0);
    CHECK(memcmp(owner,owner_before,sizeof owner)==0 && memcmp(factory_type,type_before,sizeof factory_type)==0 && memcmp(catalog,catalog_before,sizeof catalog)==0);
    expected_buckets[type_index][0]=previous_count?ptr(previous[0]):ptr(node);expected_buckets[type_index][1]=ptr(node);expected_buckets[type_index][2]=previous_count+1;
    CHECK(memcmp(buckets,expected_buckets,sizeof buckets)==0);
    for(unsigned i=0;i<previous_count;i++) {
        unsigned char expected_previous[0x288];memcpy(expected_previous,previous_before[i],0x288);
        if(i+1==previous_count)WORD(expected_previous,0x27c)=ptr(node);
        CHECK(memcmp(previous[i],expected_previous,0x288)==0);
    }
    void *link=allocation_plan[link_index].p;unsigned registry_bucket=((0x2eu<<16)+seed)%bucket_count;
    CHECK(WORD(link,0)==ptr(node) && WORD(link,4)==0);
    check_registered_tables(tables,heads,1,registry_bucket,1,link,bucket_count);
    uint32_t handle[3]={0xdeadbeef,0x2e,seed};CHECK(invoke_refresh(handle,image_va(0x967f50))==node && handle[0]==ptr(node));
    source_buffers[0][0].p=link;source_buffers[0][0].size=8;memcpy(source_buffers[0][0].before,link,8);
    free_plan_count=0;
    for(int j=7;j>=0;j--)if(source_buffers[1][j].p)free_plan[free_plan_count++]=&source_buffers[1][j];
    free_plan[free_plan_count++]=&source_buffers[0][0];
    old_array=node;expected_bytes=0x288;memcpy(expected_old,expected_node,0x288);destructor_model(expected_old);WORD(expected_old,8)=seed;WORD(expected_old,12)=0xfffe;
    current_header=bucket;old_header[0]=previous_count?ptr(previous[0]):0;old_header[1]=previous_count?ptr(previous[previous_count-1]):0;old_header[2]=previous_count+1;
    registered_link_expected=link;registered_table_expected=tables[1];registered_heads_expected=heads[1];registered_bucket_expected=registry_bucket;
    CHECK(invoke_unlink(bucket,node,image_va(0x4be8d0))==1);
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(after_fs));__asm__ __volatile__("fxrstor %0"::"m"(saved_fx));
    CHECK(after_fs==before_fs && call_frees==active+2 && registered_link_expected==NULL);
    expected_buckets[type_index][0]=previous_count?ptr(previous[0]):0;expected_buckets[type_index][1]=previous_count?ptr(previous[previous_count-1]):0;expected_buckets[type_index][2]=previous_count;
    CHECK(memcmp(buckets,expected_buckets,sizeof buckets)==0);
    check_registered_tables(tables,heads,1,registry_bucket,0,NULL,bucket_count);
    CHECK(invoke_refresh(handle,image_va(0x967f50))==NULL && handle[0]==0);
    CHECK(memcmp(owner,owner_before,sizeof owner)==0 && memcmp(factory_type,type_before,sizeof factory_type)==0 && memcmp(catalog,catalog_before,sizeof catalog)==0);
    for(unsigned i=0;i<previous_count;i++) {CHECK(memcmp(previous[i],previous_before[i],0x288)==0);CHECK(HeapFree(fixture_heap,0,previous[i]));}
    WORD(private_image,0x1258a94-0x400000)=WORD(private_image,0x1258a98-0x400000)=0;
    if(internal) {
        CHECK(memcmp(selector_types,selector_types_before,sizeof selector_types)==0);
        CHECK(memcmp(internal_array,internal_array_before,sizeof internal_array)==0 && memcmp(internal_header,internal_header_before,sizeof internal_header)==0);
        CHECK(memcmp(internal_rows,internal_rows_before,sizeof internal_rows)==0 && memcmp(internal_singleton,internal_singleton_before,sizeof internal_singleton)==0);
        CHECK(WORD(private_image,0x1258728-0x400000)==ptr(internal_singleton));WORD(private_image,0x1258728-0x400000)=0;
        printf("{\"kind\":\"case\",\"entry\":\"factory_internal_integration\",\"province_index\":%u,\"row_count\":%u,\"sequence_base3\":%u,\"predicate\":%u,\"fallback_index\":%u,\"result_fallback\":%u,\"type_index\":%u,\"original_heap_allocs\":%u,\"original_heap_frees\":%u}\n",internal->province,internal->count,internal->sequence,internal->predicate,internal->fallback_index,chosen_type==selector_types[0],type_index,call_allocs,call_frees);
    }
    else if(consume && consume->selector) {
        CHECK(memcmp(selector_types,selector_types_before,sizeof selector_types)==0);
        printf("{\"kind\":\"case\",\"entry\":\"pop_consumer_type_selection\",\"special\":%u,\"source_level\":%u,\"catalog_count\":%u,\"levels\":[%u,%u,%u],\"predicates\":[%u,%u,%u],\"flags\":[%u,%u,%u],\"selected_ordinal\":%d,\"type_index\":%u,\"original_heap_allocs\":%u,\"original_heap_frees\":%u}\n",consume->special,consume->source_level,consume->selector_count,consume->selector_levels[0],consume->selector_levels[1],consume->selector_levels[2],consume->selector_predicates[0],consume->selector_predicates[1],consume->selector_predicates[2],consume->selector_flags[0],consume->selector_flags[1],consume->selector_flags[2],chosen_ordinal,type_index,call_allocs,call_frees);
    }
    else if(consume)printf("{\"kind\":\"case\",\"entry\":\"pop_consumer_new_node\",\"size\":%u,\"slot\":%u,\"other_region\":%u,\"balance_bits\":\"%016llx\",\"type_index\":%u,\"pattern\":%u,\"original_heap_allocs\":%u,\"original_heap_frees\":%u}\n",consume->size,consume->slot,consume->other_region,(unsigned long long)consume->balance,type_index,pattern,call_allocs,call_frees);
    else printf("{\"kind\":\"case\",\"entry\":\"pop_factory_lifecycle\",\"type_index\":%u,\"previous_count\":%u,\"id_seed\":%u,\"buckets\":%u,\"pattern\":%u,\"catalog_a_count\":%u,\"catalog_b_count\":%u,\"key_type\":46,\"key_id\":%u,\"original_heap_allocs\":%u,\"original_heap_frees\":%u}\n",type_index,previous_count,seed,bucket_count,pattern,a,b,seed,call_allocs,call_frees+temporary_frees);
    cases++;
}
extern void *__cdecl invoke_internal_selector(void *requested,void *owner,void *entry,uint32_t *registers);
__asm__(
    ".text\n.globl _invoke_internal_selector\n_invoke_internal_selector:\n"
    "pushl %ebx\npushl %esi\npushl %edi\npushl %ebp\n"
    "movl 20(%esp),%eax\nmovl 24(%esp),%edx\nmovl 28(%esp),%ecx\n"
    "pushl %edx\npushl %eax\nmovl $0x12345678,%ebx\nmovl $0x23456789,%esi\nmovl $0x3456789a,%edi\nmovl $0x456789ab,%ebp\n"
    "call *%ecx\naddl $8,%esp\nmovl 32(%esp),%edx\nmovl %ebx,0(%edx)\nmovl %esi,4(%edx)\nmovl %edi,8(%edx)\nmovl %ebp,12(%edx)\n"
    "popl %ebp\npopl %edi\npopl %esi\npopl %ebx\nret\n"
);
static void run_internal_selector_case(unsigned province_index,unsigned count,unsigned sequence,unsigned predicate,unsigned pattern) {
    unsigned char requested[0x400]={0},fallback[0x400]={0},other[0x400]={0},owner[0x400]={0};
    unsigned char stats_array[4*0xb0]={0},headers[4][0x110]={{0}},rows[4][4][0x20];
    unsigned char requested_before[sizeof requested],fallback_before[sizeof fallback],other_before[sizeof other],owner_before[sizeof owner];
    unsigned char array_before[sizeof stats_array],headers_before[sizeof headers],rows_before[sizeof rows];
    uint32_t singleton[5],singleton_before[5],registers[4],before_fs,after_fs;
    CHECK(province_index<4 && count<=4 && predicate<=1);
    memset(rows,pattern,sizeof rows);memset(singleton,pattern,sizeof singleton);
    WORD(requested,0)=WORD(other,0)=ptr(image_va(0xe365f8));WORD(fallback,0)=ptr(image_va(predicate?0xe365f8:0xe36618));
    WORD(requested,0x3d4)=ptr(fallback);WORD(owner,0x58)=province_index;singleton[0]=ptr(stats_array);
    void *expected=requested;unsigned code=sequence;
    for(unsigned i=0;i<4;i++) {
        WORD(stats_array,i*0xb0+8)=ptr(headers[i]);
        WORD(headers[i],0x108)=ptr(rows[i]);WORD(headers[i],0x10c)=ptr(rows[i])+0x20*(i==province_index?count:4);
        for(unsigned j=0;j<4;j++)WORD(rows[i][j],8)=ptr(other);
    }
    if(count==0 && pattern==0)WORD(headers[province_index],0x108)=WORD(headers[province_index],0x10c)=0;
    unsigned found=0;
    for(unsigned j=0;j<count;j++) {
        unsigned value=code%3;code/=3;
        void *type=value==1?(void *)requested:value==2?(void *)fallback:(void *)other;
        WORD(rows[province_index][j],8)=ptr(type);
        if(predicate && !found && value) {expected=type;found=1;}
    }
    memcpy(requested_before,requested,sizeof requested);memcpy(fallback_before,fallback,sizeof fallback);memcpy(other_before,other,sizeof other);memcpy(owner_before,owner,sizeof owner);
    memcpy(array_before,stats_array,sizeof stats_array);memcpy(headers_before,headers,sizeof headers);memcpy(rows_before,rows,sizeof rows);memcpy(singleton_before,singleton,sizeof singleton);
    WORD(private_image,0x1258728-0x400000)=ptr(singleton);
    plan_count=free_plan_count=call_allocs=call_frees=0;old_array=NULL;factory_temp_remaining=copy_intermediate_free=0;registered_link_expected=NULL;
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(before_fs));
    void *result=invoke_internal_selector(requested,owner,image_va(0x4b8c80),registers);
    __asm__ __volatile__("movl %%fs:0,%0":"=r"(after_fs));
    CHECK(result==expected && call_allocs==0 && call_frees==0 && before_fs==after_fs);
    CHECK(registers[0]==0x12345678 && registers[1]==0x23456789 && registers[2]==0x3456789a && registers[3]==0x456789ab);
    CHECK(memcmp(requested,requested_before,sizeof requested)==0 && memcmp(fallback,fallback_before,sizeof fallback)==0 && memcmp(other,other_before,sizeof other)==0 && memcmp(owner,owner_before,sizeof owner)==0);
    CHECK(memcmp(stats_array,array_before,sizeof stats_array)==0 && memcmp(headers,headers_before,sizeof headers)==0 && memcmp(rows,rows_before,sizeof rows)==0 && memcmp(singleton,singleton_before,sizeof singleton)==0);
    CHECK(WORD(private_image,0x1258728-0x400000)==ptr(singleton));WORD(private_image,0x1258728-0x400000)=0;
    printf("{\"kind\":\"case\",\"entry\":\"factory_internal_selector\",\"province_index\":%u,\"row_count\":%u,\"sequence_base3\":%u,\"predicate\":%u,\"pattern\":%u,\"result_fallback\":%u,\"original_heap_allocs\":%u,\"original_heap_frees\":%u}\n",province_index,count,sequence,predicate,pattern,result==fallback,call_allocs,call_frees);
    cases++;
}
int main(int argc,char **argv) {
    CHECK(argc==2);SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    CHECK(AddVectoredExceptionHandler(1,unexpected_exception)!=NULL);
    fixture_heap=HeapCreate(0,0,0);CHECK(fixture_heap!=NULL);map_reference(argv[1]);
    WORD(private_image,0x1268fec-0x400000)=0x76543210;
    WORD(private_image,0x1268ff0-0x400000)=0xfedcba98;
    WORD(private_image,0x131bb34-0x400000)=ptr(catalog+0x100);
    WORD(private_image,0x12586dc-0x400000)=ptr(catalog+0x200);
    WORD(private_image,0x1258a48-0x400000)=ptr(catalog+0x40);
    WORD(private_image,0x1258a3c-0x400000)=ptr(catalog);
    const unsigned lengths[]={0,1,2,3,5,8,16},patterns[]={0,0x5a,0xff};
    for(unsigned p=0;p<3;p++)for(unsigned j=0;j<sizeof lengths/sizeof *lengths;j++)
        for(int i=-1;i<(int)lengths[j];i++)run_case(lengths[j],i,patterns[p],0);
    for(unsigned p=0;p<3;p++)for(unsigned profile=1;profile<=4;profile++)for(unsigned n=0;n<=3;n++)
        for(int i=-1;i<(int)n;i++)run_case(n,i,patterns[p],profile);
    const unsigned catalog_lengths[6][2]={{1,3},{3,1},{7,3},{3,7},{0,3},{3,0}};
    for(unsigned p=0;p<3;p++)for(unsigned k=0;k<6;k++)for(unsigned surplus=0;surplus<=2;surplus+=2) {
        prepare_catalogs(catalog_lengths[k][0],catalog_lengths[k][1],surplus);
        for(unsigned n=0;n<=2;n++)for(int i=-1;i<(int)n;i++)run_case(n,i,patterns[p],5);
    }
    const unsigned constructor_lengths[4]={0,1,3,7};
    for(unsigned p=0;p<3;p++)for(unsigned x=0;x<4;x++)for(unsigned y=0;y<4;y++)for(unsigned mode=0;mode<4;mode++)
        for(unsigned optional=0;optional<=1;optional++)run_constructor_case(constructor_lengths[x],constructor_lengths[y],patterns[p],mode,optional);
    /* m=6,n=7 exercises geometric capacity9 and its unused tail, not just exact-n growth. */
    const unsigned pool_lengths[5]={0,1,2,7,16},destination_lengths[4]={0,1,3,6},map_lengths[4]={0,1,31,64};
    for(unsigned x=0;x<5;x++)for(unsigned y=0;y<4;y++)for(unsigned mode=0;mode<2;mode++)for(unsigned k=0;k<4;k++)for(unsigned p=0;p<3;p++) {
        unsigned n=pool_lengths[x],m=destination_lengths[y],cap=mode?(n>m?n:m)+2:m;
        run_pool_copy_case(n,m,cap,map_lengths[k],patterns[p]);
    }
    const unsigned second_pool_lengths[3]={1,3,7};
    for(unsigned x=0;x<5;x++)for(unsigned y=0;y<3;y++)for(unsigned k=0;k<4;k++)for(unsigned p=0;p<3;p++)
        run_optional_copy_case(pool_lengths[x],second_pool_lengths[y],map_lengths[k],patterns[p],0,0,0);
    const unsigned combined_pool_lengths[3]={0,2,7};
    for(unsigned c=0;c<6;c++)for(unsigned extra=0;extra<=2;extra+=2)for(unsigned x=0;x<3;x++)for(unsigned k=0;k<2;k++)for(unsigned p=0;p<3;p++)
        run_optional_copy_case(combined_pool_lengths[x],3,k?64:0,patterns[p],catalog_lengths[c][0],catalog_lengths[c][1],extra);
    const unsigned registry_kinds[4]={0,0x1268,0x1269,0xffffffff},registry_ids[3]={17,0x80000000,0xffffffff},bucket_counts[3]={1,3,7};
    for(unsigned k=0;k<4;k++)for(unsigned i=0;i<3;i++)for(unsigned b=0;b<3;b++)for(unsigned p=0;p<3;p++)for(unsigned mode=0;mode<=1;mode++)
        run_registered_copy_case(registry_kinds[k],registry_ids[i],bucket_counts[b],patterns[p],mode);
    const unsigned factory_seeds[5]={0,1,0x7fffffff,0x80000000,0xffffffff};
    for(unsigned t=0;t<3;t++)for(unsigned n=0;n<=2;n++)for(unsigned s=0;s<5;s++)for(unsigned b=0;b<3;b++)for(unsigned p=0;p<3;p++)
        run_factory_case(t,n,factory_seeds[s],bucket_counts[b],patterns[p],0,0,NULL,NULL);
    for(unsigned c=0;c<6;c++)for(unsigned t=0;t<3;t++)for(unsigned n=0;n<=2;n++)for(unsigned s=0;s<2;s++)for(unsigned b=0;b<2;b++)for(unsigned p=0;p<3;p++)
        run_factory_case(t,n,s?0xffffffff:0,b?7:1,patterns[p],catalog_lengths[c][0],catalog_lengths[c][1],NULL,NULL);
    const unsigned consumer_sizes[5]={1,65535,65536,2000000,2000001};
    const uint64_t consumer_balances[4]={0,32768000,UINT64_C(0xffffffffffffffff),UINT64_C(0x7fffffffffffffff)};
    for(unsigned t=0;t<3;t++)for(unsigned slot=0;slot<3;slot++)for(unsigned n=0;n<5;n++)for(unsigned b=0;b<4;b++)for(unsigned other=0;other<2;other++)for(unsigned p=0;p<3;p++) {
        consumer_options options={.size=consumer_sizes[n],.slot=slot,.other_region=other,.balance=consumer_balances[b]};
        run_factory_case(t,0,0xffffffff,7,patterns[p],0,0,&options,NULL);
    }
    const unsigned merge_sizes[4][2]={{1,0},{1000,17},{2000000,1999999},{2000001,2000000}};
    const uint64_t merge_attributes[8][2]={{0,32768},{32768,0},{UINT64_MAX,32768},{1,UINT64_MAX},{UINT64_C(0x7fffffffffffffff),1},{UINT64_C(0x8000000000000000),0},{UINT64_C(0x123456789abcdef),UINT64_C(0xfedcba9876543210)},{32768,65536}};
    const uint64_t merge_balances[6][2]={{0,0},{32768000,11},{UINT64_MAX,7},{1,UINT64_C(0x7fffffffffffffff)},{UINT64_C(0x8000000000000000),UINT64_MAX},{UINT64_C(0x7fffffffffffffff),UINT64_C(0x7fffffffffffffff)}};
    for(unsigned n=0;n<4;n++)for(unsigned a=0;a<8;a++)for(unsigned b=0;b<6;b++)for(unsigned other=0;other<2;other++)for(unsigned p=0;p<3;p++) {
        consumer_options options={.size=merge_sizes[n][0],.slot=(n+a)%3,.other_region=other,.balance=merge_balances[b][0],.merge=1,.destination_size=merge_sizes[n][1],.destination_balance=merge_balances[b][1],.source_attribute=merge_attributes[a][0],.destination_attribute=merge_attributes[a][1]};
        run_factory_case((n+a+b)%3,1,0x80000000,7,patterns[p],0,0,&options,NULL);
    }
    const unsigned permutations[6][3]={{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}};
    const unsigned selector_levels[4][4]={{10,5,1,7},{0,0x80000000,0xffffffff,0x7fffffff},{0xffffffff,0x80000000,0,0xffffffff},{0x7fffffff,0x7ffffffe,0x7fffffff,0}};
    const unsigned predicate_masks[8]={7,7,7,7,0,1,3,5},flag_masks[8]={0,1,2,4,0,0,0,2};
    for(unsigned permutation=0;permutation<6;permutation++)for(unsigned levels=0;levels<4;levels++)for(unsigned mode=0;mode<8;mode++)for(unsigned count=0;count<=3;count++)for(unsigned special=0;special<=1;special++) {
        consumer_options options={.size=65536,.slot=permutation%3,.other_region=permutation%2,.balance=32768000,.selector=1,.special=special,.source_level=selector_levels[levels][0],.selector_count=count};
        for(unsigned i=0;i<3;i++) {options.selector_levels[i]=selector_levels[levels][1+permutations[permutation][i]];options.selector_predicates[i]=(predicate_masks[mode]>>i)&1;options.selector_flags[i]=(flag_masks[mode]>>i)&1;}
        run_factory_case(0,0,0xffffffff,7,patterns[mode%3],0,0,&options,NULL);
    }
    const unsigned province_indices[3]={0,1,3};unsigned combinations=1;
    for(unsigned count=0;count<=4;count++) {
        for(unsigned sequence=0;sequence<combinations;sequence++)for(unsigned province=0;province<3;province++)for(unsigned predicate=0;predicate<=1;predicate++)for(unsigned p=0;p<3;p++)
            run_internal_selector_case(province_indices[province],count,sequence,predicate,patterns[p]);
        combinations*=3;
    }
    unsigned integration_combinations=1;
    for(unsigned count=0;count<=3;count++) {
        for(unsigned sequence=0;sequence<integration_combinations;sequence++)for(unsigned province=0;province<2;province++)for(unsigned predicate=0;predicate<=1;predicate++)for(unsigned p=0;p<3;p++)for(unsigned index=1;index<=2;index++) {
            factory_options options={province?3:0,count,sequence,predicate,index};
            run_factory_case(0,0,0xffffffff,7,patterns[p],0,0,NULL,&options);
        }
        integration_combinations*=3;
    }
    CHECK(HeapDestroy(fixture_heap));CHECK(VirtualFree(private_image,0,MEM_RELEASE));
    printf("{\"kind\":\"summary\",\"pass\":true,\"pointer_bytes\":4,\"cases\":%u,\"actual_heap_allocs\":%u,\"actual_heap_frees\":%u,\"pre_free_snapshots\":%u,\"highlow_relocations\":%u,\"catalog_words_checked\":%u}\n",cases,total_allocs,total_frees,snapshots,relocation_count,catalog_words_checked);
    return 0;
}
