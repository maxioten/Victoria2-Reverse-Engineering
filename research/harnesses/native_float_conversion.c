/* Original CRT conversion block mapped with its PE HIGHLOW relocations.
 * Inputs are binary64 or canonical extended80 patterns. The bridge loads ST(0), sets masked
 * floating-point controls, records EDX:EAX and state, then restores host FPU state.
 * No C floating-to-integer conversion is used as an oracle. */
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "original_float_bytes.h"

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "CHECK line %d: %s\n", __LINE__, #c); return 2; } } while (0)
_Static_assert(sizeof(void *) == 4, "PE32 required");
typedef struct { uint32_t eax, edx; uint16_t cw, sw; uint32_t mxcsr; uint16_t tags, reserved; } observed;
typedef struct { unsigned char raw[10]; uint16_t format; uint32_t reserved; } fixture;
_Static_assert(sizeof(observed) == 20, "Observation ABI changed");
_Static_assert(sizeof(fixture) == 16 && offsetof(fixture, format) == 10, "Fixture ABI changed");
extern void __cdecl invoke_float(const fixture *bits, void *entry, unsigned cw, unsigned mxcsr, observed *out);
__asm__(
    ".text\n.globl _invoke_float\n_invoke_float:\n"
    "pushl %ebp\nmovl %esp, %ebp\npushl %ebx\npushl %esi\npushl %edi\n"
    "andl $-16, %esp\nsubl $0x220, %esp\nfxsave (%esp)\nfninit\n"
    "fldcw 16(%ebp)\nldmxcsr 20(%ebp)\nmovl 8(%ebp), %ebx\ncmpw $0, 10(%ebx)\njne 1f\n"
    "fldl (%ebx)\njmp 2f\n1:\nfldt (%ebx)\n2:\n"
    "movl $0xa1a2a3a4, %edx\ncall *12(%ebp)\nmovl 24(%ebp), %ebx\n"
    "movl %eax, (%ebx)\nmovl %edx, 4(%ebx)\nfnstcw 8(%ebx)\nfnstsw 10(%ebx)\nstmxcsr 12(%ebx)\n"
    "fnstenv 512(%esp)\nmovzwl 520(%esp), %ecx\nmovw %cx, 16(%ebx)\n"
    "fxrstor (%esp)\nleal -12(%ebp), %esp\npopl %edi\npopl %esi\npopl %ebx\npopl %ebp\nret\n"
);
static LONG CALLBACK unexpected_exception(EXCEPTION_POINTERS *info) {
    fprintf(stderr, "Unexpected exception %08lx at %p\n", info->ExceptionRecord->ExceptionCode,
            info->ExceptionRecord->ExceptionAddress);
    ExitProcess(3); return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    CHECK(AddVectoredExceptionHandler(1, unexpected_exception) != NULL);
    FILE *fixtures = fopen(argv[1], "rb"); CHECK(fixtures != NULL);
    unsigned char *image = VirtualAlloc(NULL, 0x1092000, MEM_RESERVE, PAGE_NOACCESS);
    CHECK(image != NULL);
    CHECK(VirtualAlloc(image + 0x731000, 0x1000, MEM_COMMIT, PAGE_READWRITE) == image + 0x731000);
    CHECK(VirtualAlloc(image + 0xff3000, 0x1000, MEM_COMMIT, PAGE_READWRITE) == image + 0xff3000);
    unsigned char *entry = image + 0x731c00;
    memcpy(entry, original_float_block, sizeof original_float_block);
    uint32_t delta = (uint32_t)(uintptr_t)image - 0x400000;
    for (unsigned i=0; i<sizeof original_float_fixups / sizeof *original_float_fixups; i++)
        *(uint32_t *)(entry + original_float_fixups[i]) += delta;
    DWORD old;
    CHECK(VirtualProtect(image + 0x731000, 0x1000, PAGE_EXECUTE_READ, &old));
    CHECK(FlushInstructionCache(GetCurrentProcess(), entry, sizeof original_float_block));
    const unsigned offsets[] = {0, 0x1c, 0x36};
    fixture input;
    unsigned records = 0, cases = 0;
    for (;;) {
        size_t got = fread(&input, 1, sizeof input, fixtures);
        if (!got && feof(fixtures)) break;
        CHECK(got == sizeof input && input.format <= 1 && input.reserved == 0);
        for (unsigned flag=0; flag<2; flag++) for (unsigned e=0; e<3; e++)
            for (unsigned rounding=0; rounding<4; rounding++) {
                *(uint32_t *)(image + 0xff3be0) = flag;
                unsigned cw = 0x37f | (rounding << 10), mxcsr = 0x1f80 | (rounding << 13);
                observed out;
                invoke_float(&input, entry + offsets[e], cw, mxcsr, &out);
                CHECK(out.cw == cw && (out.sw & 0x3800) == 0 && out.tags == 0xffff);
                CHECK((out.mxcsr & ~0x3fu) == mxcsr);
                printf("{\"kind\":\"case\",\"record\":%u,\"input_format\":%u,\"input_bits\":\"", records, (unsigned)input.format);
                for (int i=input.format ? 9 : 7; i>=0; i--) printf("%02x", (unsigned)input.raw[i]);
                printf("\",\"entry_offset\":%u,\"flag\":%u,\"rounding\":%u,\"eax\":%lu,\"edx\":%lu,\"cw\":%u,\"sw\":%u,\"mxcsr\":%lu,\"tags\":%u}\n",
                       offsets[e], flag, rounding,
                       (unsigned long)out.eax, (unsigned long)out.edx, (unsigned)out.cw, (unsigned)out.sw,
                       (unsigned long)out.mxcsr, (unsigned)out.tags);
                cases++;
            }
        records++;
    }
    CHECK(!ferror(fixtures) && fclose(fixtures) == 0);
    printf("{\"kind\":\"summary\",\"pass\":true,\"pointer_bytes\":4,\"records\":%u,\"cases\":%u,\"private_image_base\":%lu}\n",
           records, cases, (unsigned long)(uintptr_t)image);
    CHECK(VirtualFree(image, 0, MEM_RELEASE));
    return 0;
}
