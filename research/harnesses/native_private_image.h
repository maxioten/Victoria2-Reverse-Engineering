/* Isolated PE32 loader copied from the validated lifetime probe; no entry/TLS. */
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

