/* Executes the two original position-independent helper bodies in a PE32 process.
 * Expected values come from Python-generated fixtures, not the C compiler's division.
 * No game process, game globals, imports or heap internals are reconstructed here. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "original_integer_bytes.h"

typedef uint64_t (__stdcall *binary64)(uint64_t, uint64_t);
#pragma pack(push, 1)
typedef struct { uint64_t a, b, quotient, product; uint32_t divide_enabled; } fixture;
#pragma pack(pop)
_Static_assert(sizeof(void *) == 4, "Must build PE32");
_Static_assert(sizeof(fixture) == 36, "Fixture format changed");

static void *executable_copy(const unsigned char *source, SIZE_T size) {
    void *memory = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    DWORD old_protection;
    if (!memory) return NULL;
    memcpy(memory, source, size);
    if (!VirtualProtect(memory, size, PAGE_EXECUTE_READ, &old_protection)) {
        VirtualFree(memory, 0, MEM_RELEASE); return NULL;
    }
    FlushInstructionCache(GetCurrentProcess(), memory, size);
    return memory;
}

int main(int argc, char **argv) {
    unsigned divisions = 0, products = 0, records = 0;
    fixture input;
    if (argc != 2) { fprintf(stderr, "Expected fixture path\n"); return 2; }
    FILE *source = fopen(argv[1], "rb");
    if (!source) { perror("fixtures"); return 2; }
    void *divide_memory = executable_copy(original_divide, sizeof original_divide);
    void *multiply_memory = executable_copy(original_multiply, sizeof original_multiply);
    if (!divide_memory || !multiply_memory) { fprintf(stderr, "Executable allocation failed\n"); return 2; }
    binary64 divide = (binary64)divide_memory, multiply = (binary64)multiply_memory;
    for (;;) {
        size_t got = fread(&input, 1, sizeof input, source);
        if (got == 0 && feof(source)) break;
        if (got != sizeof input) { fprintf(stderr, "Incomplete fixture\n"); return 2; }
        uint64_t product = multiply(input.a, input.b);
        if (product != input.product) {
            fprintf(stderr, "Product mismatch at record %u\n", records); return 1;
        }
        products++;
        if (input.divide_enabled) {
            if (input.b == 0) { fprintf(stderr, "Invalid nonzero-divisor fixture\n"); return 2; }
            uint64_t quotient = divide(input.a, input.b);
            if (quotient != input.quotient) {
                fprintf(stderr, "Quotient mismatch at record %u\n", records); return 1;
            }
            divisions++;
        }
        records++;
    }
    if (ferror(source) || fclose(source)) { fprintf(stderr, "Fixture read error\n"); return 2; }
    VirtualFree(divide_memory, 0, MEM_RELEASE);
    VirtualFree(multiply_memory, 0, MEM_RELEASE);
    printf("{\"pass\":true,\"pointer_bytes\":4,\"records\":%u,\"division_cases\":%u,\"multiplication_cases\":%u}\n",
           records, divisions, products);
    return 0;
}
