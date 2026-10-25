/* Isolated PE32 fixture harness. Maps a private reference image at a separate
 * base using PE HIGHLOW loader relocations, without entry points, TLS or engine initialization.
 * Installed imports forward to real Win32 HeapAlloc, HeapFree and SwitchToThread,
 * recording fixture events without replacing their successful behavior.
 * All objects are synthetic HeapAlloc allocations, never live game objects. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(void *) == 4, "PE32 required");
#define WORD(p, o) (*(uint32_t *)((unsigned char *)(p) + (o)))
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "CHECK line %d: %s\n", __LINE__, #c); ExitProcess(2); } } while (0)
static HANDLE fixture_heap;
static void *expected_free[20], *target_node, *optional_object;
static unsigned char expected_target[0x288], expected_optional[0xc0];
static void *regiments[3], *reference_vector;
static unsigned char expected_regiments[3][0x100], expected_reference_vector[32];
static unsigned regiment_count;
static unsigned expected_count, observed_count, total_frees, snapshots, case_count;
static unsigned relocation_count;
static unsigned char *private_image;
static uint32_t *active_bucket;
static unsigned original_count;
static int registry_mode;
static BOOL record_registry_free(LPVOID pointer);
static BOOL record_integrated_pop_free(LPVOID pointer);
static unsigned allocation_mode, allocation_calls, total_allocations;
static void *last_allocation;
static volatile LONG lock_yields;
static HANDLE lock_yield_event;
static BOOL WINAPI recorded_switch_to_thread(void) {
    InterlockedIncrement(&lock_yields);
    if (lock_yield_event) CHECK(SetEvent(lock_yield_event));
    return SwitchToThread();
}

static LPVOID WINAPI recorded_heap_alloc(HANDLE heap, DWORD flags, SIZE_T size) {
    CHECK(allocation_mode && heap == fixture_heap && flags == 0 && size == 8);
    void *pointer = HeapAlloc(heap, flags, size);
    CHECK(pointer != NULL);
    last_allocation = pointer;
    allocation_calls++; total_allocations++;
    return pointer;
}

static LONG CALLBACK unexpected_exception(EXCEPTION_POINTERS *info) {
    fprintf(stderr, "Unexpected exception %08lx at %p\n",
            info->ExceptionRecord->ExceptionCode, info->ExceptionRecord->ExceptionAddress);
    ExitProcess(3);
    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL WINAPI recorded_heap_free(HANDLE heap, DWORD flags, LPVOID pointer) {
    CHECK(heap == fixture_heap && flags == 0);
    if (registry_mode == 1) return record_registry_free(pointer);
    if (registry_mode == 2) return record_integrated_pop_free(pointer);
    CHECK(observed_count < expected_count);
    CHECK(pointer == expected_free[observed_count]);
    CHECK(active_bucket[2] == original_count); /* decrement follows actual node free */
    CHECK(HeapSize(heap, 0, pointer) != (SIZE_T)-1);
    for (unsigned i = 0; i < regiment_count; i++) if (pointer == regiments[i]) {
        CHECK(memcmp(pointer, expected_regiments[i], 0x100) == 0);
        CHECK(WORD(target_node, 0x40) == WORD(target_node, 0x3c) + (regiment_count - i - 1) * 4);
        for (unsigned j = i+1; j < regiment_count; j++)
            CHECK(WORD(reference_vector, (j-i-1)*4) == (uint32_t)(uintptr_t)regiments[j]);
        snapshots++;
    }
    if (pointer == reference_vector) CHECK(memcmp(pointer, expected_reference_vector, 32) == 0);
    if (pointer == optional_object) {
        CHECK(memcmp(pointer, expected_optional, sizeof expected_optional) == 0);
        snapshots++;
    }
    if (pointer == target_node) {
        CHECK(memcmp(pointer, expected_target, sizeof expected_target) == 0);
        snapshots++;
    }
    CHECK(HeapFree(heap, flags, pointer));
    observed_count++;
    total_frees++;
    return TRUE;
}

/* The original unlink entry takes bucket in ESI and one stack argument, RET 4.
 * Separate handwritten bridge preserves the C caller's ESI and stack ABI. */
extern unsigned __cdecl invoke_unlink(void *bucket, void *node, void *entry);
__asm__(
    ".text\n"
    ".globl _invoke_unlink\n"
    "_invoke_unlink:\n"
    "pushl %esi\n"
    "movl 8(%esp), %esi\n"
    "movl 16(%esp), %eax\n"
    "pushl 12(%esp)\n"
    "call *%eax\n"
    "movzbl %al, %eax\n"
    "popl %esi\n"
    "ret\n"
);

static void map_reference(const char *path) {
    FILE *f = fopen(path, "rb");
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS32 nt;
    CHECK(f != NULL);
    CHECK(fread(&dos, sizeof dos, 1, f) == 1 && dos.e_magic == IMAGE_DOS_SIGNATURE);
    CHECK(fseek(f, dos.e_lfanew, SEEK_SET) == 0);
    CHECK(fread(&nt, sizeof nt, 1, f) == 1 && nt.Signature == IMAGE_NT_SIGNATURE);
    CHECK(nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    CHECK(nt.OptionalHeader.ImageBase == 0x400000);
    CHECK(nt.OptionalHeader.SizeOfImage == 0x1092000);
    unsigned char *image = VirtualAlloc((void *)0x30000000, nt.OptionalHeader.SizeOfImage,
                                       MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (image != (void *)0x30000000) {
        fprintf(stderr, "Reference reservation failed: error=%lu, harness=%p\n", GetLastError(), GetModuleHandleA(NULL));
        uintptr_t at = 0x30000000, end = at + nt.OptionalHeader.SizeOfImage;
        while (at < end) {
            MEMORY_BASIC_INFORMATION region;
            CHECK(VirtualQuery((void *)at, &region, sizeof region) == sizeof region);
            if (region.State != MEM_FREE) {
                char path[MAX_PATH] = {0};
                GetModuleFileNameA((HMODULE)region.AllocationBase, path, sizeof path);
                fprintf(stderr, "Occupied %p + %lx state=%lx type=%lx allocation=%p module=%s\n",
                        region.BaseAddress, (unsigned long)region.RegionSize, region.State,
                        region.Type, region.AllocationBase, path);
            }
            at = (uintptr_t)region.BaseAddress + region.RegionSize;
        }
    }
    CHECK(image == (void *)0x30000000);
    private_image = image;
    CHECK(fseek(f, 0, SEEK_SET) == 0);
    CHECK(fread(image, 1, nt.OptionalHeader.SizeOfHeaders, f) == nt.OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION((IMAGE_NT_HEADERS32 *)(image + dos.e_lfanew));
    for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER *s = &sections[i];
        CHECK(s->VirtualAddress < nt.OptionalHeader.SizeOfImage);
        CHECK(s->SizeOfRawData <= nt.OptionalHeader.SizeOfImage - s->VirtualAddress);
        if (!s->SizeOfRawData) continue;
        CHECK(fseek(f, s->PointerToRawData, SEEK_SET) == 0);
        CHECK(fread(image + s->VirtualAddress, 1, s->SizeOfRawData, f) == s->SizeOfRawData);
    }
    CHECK(fclose(f) == 0);
    IMAGE_DATA_DIRECTORY reloc = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    CHECK(reloc.VirtualAddress == 0xff8000 && reloc.Size == 0x7f3e0);
    uint32_t delta = (uint32_t)(uintptr_t)image - nt.OptionalHeader.ImageBase;
    for (uint32_t offset = 0; offset < reloc.Size;) {
        IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION *)(image + reloc.VirtualAddress + offset);
        CHECK(block->SizeOfBlock >= 8 && !(block->SizeOfBlock & 1));
        CHECK(block->SizeOfBlock <= reloc.Size - offset);
        WORD *entries = (WORD *)(block + 1);
        for (unsigned i = 0; i < (block->SizeOfBlock - 8) / 2; i++) {
            unsigned type = entries[i] >> 12, position = entries[i] & 0xfff;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            CHECK(type == IMAGE_REL_BASED_HIGHLOW);
            CHECK(block->VirtualAddress + position <= nt.OptionalHeader.SizeOfImage - 4);
            WORD(image, block->VirtualAddress + position) += delta;
            relocation_count++;
        }
        offset += block->SizeOfBlock;
    }
    CHECK(relocation_count == 249412);
    /* Declared private fixture writes, not code patches or reference-file edits. */
    WORD(image, 0xc8a070 - 0x400000) = (uint32_t)(uintptr_t)recorded_heap_free;
    WORD(image, 0xc8a05c - 0x400000) = (uint32_t)(uintptr_t)recorded_heap_alloc;
    WORD(image, 0xc8a188 - 0x400000) = (uint32_t)(uintptr_t)recorded_switch_to_thread;
    WORD(image, 0xf202e8 - 0x400000) = (uint32_t)(uintptr_t)fixture_heap;
    WORD(image, 0x1258a94 - 0x400000) = 0;
    WORD(image, 0x1258a98 - 0x400000) = 0;
    for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER *s = &sections[i];
        DWORD old, protection;
        SIZE_T size = s->Misc.VirtualSize > s->SizeOfRawData ? s->Misc.VirtualSize : s->SizeOfRawData;
        if (!size) continue;
        if (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            CHECK(!(s->Characteristics & IMAGE_SCN_MEM_WRITE));
            protection = PAGE_EXECUTE_READ;
        } else protection = (s->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        CHECK(VirtualProtect(image + s->VirtualAddress, size, protection, &old));
    }
    DWORD old;
    CHECK(VirtualProtect(image, nt.OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old));
    CHECK(FlushInstructionCache(GetCurrentProcess(), image, nt.OptionalHeader.SizeOfImage));
}

static void *allocate(SIZE_T size) {
    void *p = HeapAlloc(fixture_heap, HEAP_ZERO_MEMORY, size);
    CHECK(p != NULL);
    return p;
}
static void triple(void *object, unsigned offset, unsigned bytes) {
    void *p = allocate(bytes);
    WORD(object, offset) = (uint32_t)(uintptr_t)p;
    WORD(object, offset + 4) = (uint32_t)(uintptr_t)p + bytes;
    WORD(object, offset + 8) = (uint32_t)(uintptr_t)p + bytes;
}
static void expect(void *p) { CHECK(expected_count < 20); expected_free[expected_count++] = p; }
static void expect_field(void *object, unsigned offset) {
    expect((void *)(uintptr_t)WORD(object, offset));
}

static void run_case(unsigned length, int selected, unsigned deferred, unsigned owned, unsigned unit_count) {
    void *nodes[3] = {NULL, NULL, NULL};
    unsigned char before[3][0x288];
    unsigned char before_regiments[3][0x100], before_reference_vector[32];
    uint32_t bucket[4] = {0, 0, length, deferred};
    static const unsigned buffers[] = {0x104, 0xf4, 0xdc, 0xcc, 0xb4, 0xa4, 0x8c, 0x7c, 0x3c};
    CHECK(length <= 3 && selected < (int)length);
    expected_count = observed_count = 0;
    optional_object = NULL;
    reference_vector = NULL;
    regiment_count = unit_count;
    CHECK(regiment_count <= 3);
    memset(regiments, 0, sizeof regiments);
    for (unsigned i = 0; i < length; i++) {
        nodes[i] = allocate(0x288);
        WORD(nodes[i], 0) = (uint32_t)(uintptr_t)private_image + 0xe36428 - 0x400000;
        WORD(nodes[i], 0x28) = WORD(nodes[i], 0x240) = 15;
        WORD(nodes[i], 0x220) = 0xa5a5a5a5;
        WORD(nodes[i], 0x224) = 0x1268;
        WORD(nodes[i], 0x228) = 17;
    }
    target_node = selected < 0 ? NULL : nodes[selected];
    if (target_node && (owned & 1)) {
        for (unsigned i = 0; i < 2; i++) {
            unsigned off = i ? 0x22c : 0x14;
            WORD(target_node, off) = (uint32_t)(uintptr_t)allocate(32);
            WORD(target_node, off + 0x10) = 20;
            WORD(target_node, off + 0x14) = 31;
        }
        for (unsigned i = 0; i < sizeof buffers / sizeof *buffers; i++) triple(target_node, buffers[i], 32);
        /* The logical reference range starts empty; optional regiment fixtures extend it. */
        WORD(target_node, 0x40) = WORD(target_node, 0x3c);
    }
    if (target_node && (owned & 2)) {
        optional_object = allocate(sizeof expected_optional);
        WORD(target_node, 0x1d4) = (uint32_t)(uintptr_t)optional_object;
        triple(optional_object, 0xa0, 24);
        triple(optional_object, 0x48, 40);
    }
    CHECK(target_node || regiment_count == 0);
    if (regiment_count) {
        if (!(owned & 1)) triple(target_node, 0x3c, 32);
        reference_vector = (void *)(uintptr_t)WORD(target_node, 0x3c);
        WORD(target_node, 0x40) = (uint32_t)(uintptr_t)reference_vector + regiment_count * 4;
        for (unsigned i = 0; i < regiment_count; i++) {
            regiments[i] = allocate(0x100); /* fixture span, not a claimed class size */
            WORD(regiments[i], 0) = (uint32_t)(uintptr_t)private_image + 0xdf8884 - 0x400000;
            WORD(regiments[i], 0x30) = (uint32_t)(uintptr_t)target_node;
            WORD(regiments[i], 0x28) = WORD(regiments[i], 0x58) = 15;
            WORD(reference_vector, i*4) = (uint32_t)(uintptr_t)regiments[i];
            memcpy(before_regiments[i], regiments[i], 0x100);
            memcpy(expected_regiments[i], regiments[i], 0x100);
            WORD(expected_regiments[i], 0) = (uint32_t)(uintptr_t)private_image + 0xe3a544 - 0x400000;
            WORD(expected_regiments[i], 0x30) = 0;
        }
    } else if (target_node) reference_vector = (void *)(uintptr_t)WORD(target_node, 0x3c);
    memset(expected_reference_vector, 0, sizeof expected_reference_vector);
    if (reference_vector) {
        memcpy(before_reference_vector, reference_vector, 32);
        for (unsigned i = 0; i < regiment_count; i++)
            WORD(expected_reference_vector, i*4) = (uint32_t)(uintptr_t)regiments[regiment_count-1];
    }
    for (unsigned i = 0; i < length; i++) {
        WORD(nodes[i], 0x278) = i ? (uint32_t)(uintptr_t)nodes[i-1] : 0;
        WORD(nodes[i], 0x27c) = i+1 < length ? (uint32_t)(uintptr_t)nodes[i+1] : 0;
        memcpy(before[i], nodes[i], 0x288);
    }
    if (length) { bucket[0] = (uint32_t)(uintptr_t)nodes[0]; bucket[1] = (uint32_t)(uintptr_t)nodes[length-1]; }
    active_bucket = bucket;
    original_count = length;
    if (target_node && !deferred) {
        memcpy(expected_target, target_node, sizeof expected_target);
        WORD(expected_target, 0) = (uint32_t)(uintptr_t)private_image + 0xe3a544 - 0x400000;
        WORD(expected_target, 0x220) = 0;
        for (unsigned i = 0; i < regiment_count; i++) expect(regiments[i]);
        if (optional_object) {
            memcpy(expected_optional, optional_object, sizeof expected_optional);
            expect_field(optional_object, 0xa0);
            expect_field(optional_object, 0x48);
            expect(optional_object);
            memset(expected_optional + 0xa0, 0, 12);
            memset(expected_optional + 0x48, 0, 12);
        }
        if (owned & 1) expect_field(target_node, 0x22c);
        for (unsigned i = 0; i < sizeof buffers / sizeof *buffers; i++) {
            if ((owned & 1) || (buffers[i] == 0x3c && regiment_count)) expect_field(target_node, buffers[i]);
            memset(expected_target + buffers[i], 0, 12);
        }
        if (owned & 1) expect_field(target_node, 0x14);
        for (unsigned i = 0; i < 2; i++) {
            unsigned off = i ? 0x22c : 0x14;
            expected_target[off] = 0;
            WORD(expected_target, off + 0x10) = 0;
            WORD(expected_target, off + 0x14) = 15;
        }
        expect(target_node);
    }
    uint32_t exception_chain_before, exception_chain_after;
    __asm__ __volatile__("movl %%fs:0, %0" : "=r"(exception_chain_before));
    unsigned result = invoke_unlink(bucket, target_node, private_image + 0x4be8d0 - 0x400000);
    __asm__ __volatile__("movl %%fs:0, %0" : "=r"(exception_chain_after));
    CHECK(exception_chain_before == exception_chain_after);
    CHECK(result == (target_node != NULL));
    CHECK(observed_count == expected_count);
    if (deferred) {
        for (unsigned i = 0; i < regiment_count; i++) CHECK(memcmp(regiments[i], before_regiments[i], 0x100) == 0);
        if (reference_vector) CHECK(memcmp(reference_vector, before_reference_vector, 32) == 0);
    }
    int removed = target_node && !deferred;
    CHECK(bucket[2] == length - removed && bucket[3] == deferred);
    void *remaining[3];
    unsigned remaining_count = 0;
    for (unsigned i = 0; i < length; i++) if (!(removed && (int)i == selected)) remaining[remaining_count++] = nodes[i];
    CHECK(bucket[0] == (remaining_count ? (uint32_t)(uintptr_t)remaining[0] : 0));
    CHECK(bucket[1] == (remaining_count ? (uint32_t)(uintptr_t)remaining[remaining_count-1] : 0));
    for (unsigned i = 0, j = 0; i < length; i++) {
        if (removed && (int)i == selected) continue;
        unsigned char expected[0x288];
        memcpy(expected, before[i], sizeof expected);
        WORD(expected, 0x278) = j ? (uint32_t)(uintptr_t)remaining[j-1] : 0;
        WORD(expected, 0x27c) = j+1 < remaining_count ? (uint32_t)(uintptr_t)remaining[j+1] : 0;
        if (nodes[i] == target_node && deferred) expected[0x280] = 1;
        CHECK(memcmp(nodes[i], expected, sizeof expected) == 0);
        j++;
    }
    CHECK(HeapValidate(fixture_heap, 0, NULL));
    /* Cleanup of untouched fixtures is host code and excluded from recorded frees. */
    for (unsigned i = 0; i < length; i++) {
        if (removed && (int)i == selected) continue;
        if (nodes[i] == target_node) {
            if (owned & 1) {
                CHECK(HeapFree(fixture_heap, 0, (void *)(uintptr_t)WORD(target_node, 0x22c)));
                CHECK(HeapFree(fixture_heap, 0, (void *)(uintptr_t)WORD(target_node, 0x14)));
                for (unsigned k = 0; k < sizeof buffers / sizeof *buffers; k++) CHECK(HeapFree(fixture_heap, 0, (void *)(uintptr_t)WORD(target_node, buffers[k])));
            }
            if (!(owned & 1) && regiment_count) CHECK(HeapFree(fixture_heap, 0, reference_vector));
            for (unsigned k = 0; k < regiment_count; k++) CHECK(HeapFree(fixture_heap, 0, regiments[k]));
            if (optional_object) {
                CHECK(HeapFree(fixture_heap, 0, (void *)(uintptr_t)WORD(optional_object, 0xa0)));
                CHECK(HeapFree(fixture_heap, 0, (void *)(uintptr_t)WORD(optional_object, 0x48)));
                CHECK(HeapFree(fixture_heap, 0, optional_object));
            }
        }
        CHECK(HeapFree(fixture_heap, 0, nodes[i]));
    }
    printf("{\"kind\":\"case\",\"length\":%u,\"selected\":%d,\"deferred\":%u,\"ownership_profile\":%u,\"regiment_count\":%u,\"original_heap_frees\":%u}\n",
           length, selected, deferred, owned, regiment_count, observed_count);
    case_count++;
}

#include "native_registry_cases.h"

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "Expected local reference path\n"); return 2; }
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    CHECK(AddVectoredExceptionHandler(1, unexpected_exception) != NULL);
    fixture_heap = HeapCreate(0, 0, 0);
    CHECK(fixture_heap != NULL);
    map_reference(argv[1]);
    unsigned char *game_state = allocate(0xd20);
    game_state[0xd1d] = 1; /* declared gate: skip country/type bookkeeping */
    game_state[0xd1c] = 0; /* declared gate: skip special REB arithmetic */
    WORD(private_image, 0x12588e8 - 0x400000) = (uint32_t)(uintptr_t)game_state;
    for (unsigned length = 0; length <= 3; length += length == 0 ? 1 : 2) {
        for (unsigned deferred = 0; deferred < 2; deferred++) {
            run_case(length, -1, deferred, 0, 0);
            for (unsigned selected = 0; selected < length; selected++)
                for (unsigned owned = 0; owned < 4; owned++)
                    for (unsigned units = 0; units <= 3; units++) run_case(length, (int)selected, deferred, owned, units);
        }
    }
    for (unsigned i = 0; i < 0xd20; i++) CHECK(game_state[i] == (i == 0xd1d ? 1 : 0));
    CHECK(HeapFree(fixture_heap, 0, game_state));
    run_registry_cases();
    run_integrated_pop_cases();
    run_spinlock_cases();
    CHECK(HeapDestroy(fixture_heap));
    CHECK(VirtualFree(private_image, 0, MEM_RELEASE));
    printf("{\"kind\":\"summary\",\"pass\":true,\"pointer_bytes\":4,\"cases\":%u,\"actual_heap_frees\":%u,\"pre_free_snapshots\":%u,\"highlow_relocations\":%u,\"registry_cases\":%u,\"registry_heap_frees\":%u,\"actual_heap_allocs\":%u,\"registered_pop_cases\":%u,\"automatic_id_cases\":%u,\"lock_cases\":%u}\n",
           case_count, total_frees, snapshots, relocation_count, registry_case_count, registry_free_count, total_allocations, registered_pop_case_count, automatic_id_case_count, lock_case_count);
    return 0;
}
