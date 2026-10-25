/* Private fixtures for 0x9C1CB0 and 0x9C1650. Included by the PE32 lifetime probe.
 * The golden chain model is row order with first exact-key removal, not generated
 * from disassembly. Real HeapFree frees only the 8-byte chain link, never its object. */
typedef struct {
    uint32_t table[3], *heads;
    void *links[16], *objects[16];
    unsigned char object_before[16][0x20];
    uint32_t kinds[16], ids[16];
    unsigned count, bucket_count;
    void *inserted_link, *inserted_object;
} registry_fixture;
static registry_fixture *current_registry;
static int registry_removed;
static unsigned registry_call_frees, registry_case_count, registry_free_count;
static unsigned registered_pop_case_count;
static unsigned automatic_id_case_count, lock_case_count;

extern unsigned __cdecl invoke_registry_remove(void *key, void *table, void *entry);
extern unsigned __cdecl invoke_registry_deregister(void *object, void *entry);
extern unsigned __cdecl invoke_registry_insert(void *object, void *entry);
extern void __cdecl invoke_registry_initialize(void *object, void *key, void *entry);
extern void *__cdecl invoke_registry_lookup(void *key, void *table, void *entry);
__asm__(
    ".text\n"
    ".globl _invoke_registry_remove\n"
    "_invoke_registry_remove:\n"
    "movl 4(%esp), %eax\n"
    "pushl 8(%esp)\n"
    "call *16(%esp)\n"
    "movzbl %al, %eax\n"
    "ret\n"
    ".globl _invoke_registry_insert\n"
    "_invoke_registry_insert:\n"
    "movl 4(%esp), %eax\n"
    "call *8(%esp)\n"
    "movzbl %al, %eax\n"
    "ret\n"
    ".globl _invoke_registry_initialize\n"
    "_invoke_registry_initialize:\n"
    "movl 4(%esp), %ecx\n"
    "pushl 8(%esp)\n"
    "call *16(%esp)\n"
    "ret\n"
    ".globl _invoke_registry_lookup\n"
    "_invoke_registry_lookup:\n"
    "movl 4(%esp), %eax\n"
    "movl 8(%esp), %ecx\n"
    "call *12(%esp)\n"
    "ret\n"
    ".globl _invoke_registry_deregister\n"
    "_invoke_registry_deregister:\n"
    "pushl %esi\n"
    "movl 8(%esp), %esi\n"
    "call *12(%esp)\n"
    "popl %esi\n"
    "movzbl %al, %eax\n"
    "ret\n"
);

static unsigned bucket_for(uint32_t kind, uint32_t id, unsigned count) {
    return ((kind << 16) + id) % count; /* uint32_t wrap is intentional */
}
static void check_registry(registry_fixture *f, int removed, int decremented) {
    CHECK(f->table[0] == f->count - (decremented && removed >= 0) + (f->inserted_link != NULL));
    CHECK(f->table[1] == f->bucket_count && f->table[2] == (uint32_t)(uintptr_t)f->heads);
    for (unsigned b = 0; b < f->bucket_count; b++) {
        uint32_t first = 0;
        for (unsigned i = 0; i < f->count; i++) {
            if ((int)i == removed || bucket_for(f->kinds[i], f->ids[i], f->bucket_count) != b) continue;
            if (!first) first = (uint32_t)(uintptr_t)f->links[i];
            uint32_t next = 0;
            for (unsigned j = i+1; j < f->count; j++) {
                if ((int)j != removed && bucket_for(f->kinds[j], f->ids[j], f->bucket_count) == b) {
                    next = (uint32_t)(uintptr_t)f->links[j]; break;
                }
            }
            CHECK(WORD(f->links[i], 0) == (uint32_t)(uintptr_t)f->objects[i]);
            CHECK(WORD(f->links[i], 4) == next);
        }
        if (f->inserted_link && bucket_for(WORD(f->inserted_object, 8), WORD(f->inserted_object, 12), f->bucket_count) == b) {
            CHECK(WORD(f->inserted_link, 0) == (uint32_t)(uintptr_t)f->inserted_object);
            CHECK(WORD(f->inserted_link, 4) == first);
            first = (uint32_t)(uintptr_t)f->inserted_link;
        }
        CHECK(f->heads[b] == first);
    }
    for (unsigned i = 0; i < f->count; i++)
        CHECK(memcmp(f->objects[i], f->object_before[i], 0x20) == 0);
}
static BOOL record_registry_free(LPVOID pointer) {
    registry_fixture *f = current_registry;
    CHECK(registry_removed >= 0 && registry_call_frees == 0);
    CHECK(pointer == f->links[registry_removed]);
    CHECK(HeapSize(fixture_heap, 0, pointer) == 8);
    CHECK(WORD(pointer, 0) == (uint32_t)(uintptr_t)f->objects[registry_removed]);
    uint32_t original_next = 0;
    unsigned b = bucket_for(f->kinds[registry_removed], f->ids[registry_removed], f->bucket_count);
    for (unsigned j = (unsigned)registry_removed+1; j < f->count; j++)
        if (bucket_for(f->kinds[j], f->ids[j], f->bucket_count) == b) { original_next = (uint32_t)(uintptr_t)f->links[j]; break; }
    CHECK(WORD(pointer, 4) == original_next);
    check_registry(f, registry_removed, 0); /* links fixed, count decremented after HeapFree */
    CHECK(HeapFree(fixture_heap, 0, pointer));
    registry_call_frees++;
    registry_free_count++;
    total_frees++;
    snapshots++;
    return TRUE;
}
static void build_registry(registry_fixture *f, unsigned count, unsigned buckets,
                           const uint32_t *kinds, const uint32_t *ids) {
    memset(f, 0, sizeof *f);
    CHECK(count <= 16 && buckets > 0);
    f->count = count; f->bucket_count = buckets;
    f->heads = allocate(buckets * 4);
    f->table[0] = count; f->table[1] = buckets; f->table[2] = (uint32_t)(uintptr_t)f->heads;
    for (unsigned i = 0; i < count; i++) {
        f->kinds[i] = kinds[i]; f->ids[i] = ids[i];
        f->objects[i] = allocate(0x20); f->links[i] = allocate(8);
        memset(f->objects[i], 0xa5, 0x20);
        WORD(f->objects[i], 8) = kinds[i]; WORD(f->objects[i], 12) = ids[i];
        memcpy(f->object_before[i], f->objects[i], 0x20);
        WORD(f->links[i], 0) = (uint32_t)(uintptr_t)f->objects[i];
        unsigned b = bucket_for(kinds[i], ids[i], buckets);
        if (!f->heads[b]) f->heads[b] = (uint32_t)(uintptr_t)f->links[i];
        for (int j = (int)i-1; j >= 0; j--) if (bucket_for(kinds[j], ids[j], buckets) == b) {
            WORD(f->links[j], 4) = (uint32_t)(uintptr_t)f->links[i]; break;
        }
    }
}
static int first_key(registry_fixture *f, uint32_t kind, uint32_t id) {
    for (unsigned i = 0; i < f->count; i++) if (f->kinds[i] == kind && f->ids[i] == id) return (int)i;
    return -1;
}
static void cleanup_registry(registry_fixture *f, int removed) {
    if (f->inserted_link) CHECK(HeapFree(fixture_heap, 0, f->inserted_link));
    for (unsigned i = 0; i < f->count; i++) {
        if ((int)i != removed) CHECK(HeapFree(fixture_heap, 0, f->links[i]));
        CHECK(HeapFree(fixture_heap, 0, f->objects[i]));
    }
    CHECK(HeapFree(fixture_heap, 0, f->heads));
}
static void direct_registry_case(unsigned count, unsigned buckets, uint32_t kind, uint32_t id) {
    uint32_t kinds[16] = {0,0,0x1268,0x1269,0xffffffff,0x80000000};
    uint32_t ids[16] = {0,0,17,18,0xffffffff,0};
    for (unsigned i = 6; i < 16; i++) { kinds[i] = i & 1 ? 0x1269 : 0x1268; ids[i] = 100+i; }
    registry_fixture f;
    build_registry(&f, count, buckets, kinds, ids);
    uint32_t key[2] = {kind, id};
    current_registry = &f; registry_removed = first_key(&f, kind, id); registry_call_frees = 0;
    unsigned result = invoke_registry_remove(key, f.table, private_image + 0x9c1cb0 - 0x400000);
    CHECK(result == (registry_removed >= 0));
    CHECK(registry_call_frees == (unsigned)(registry_removed >= 0));
    CHECK(key[0] == kind && key[1] == id);
    check_registry(&f, registry_removed, 1);
    CHECK(HeapValidate(fixture_heap, 0, NULL));
    printf("{\"kind\":\"case\",\"entry\":\"registry_remove\",\"rows\":%u,\"buckets\":%u,\"key_type\":%lu,\"key_id\":%lu,\"removed_index\":%d,\"original_heap_frees\":%u}\n",
           count, buckets, (unsigned long)kind, (unsigned long)id, registry_removed, registry_call_frees);
    cleanup_registry(&f, registry_removed);
    registry_case_count++; case_count++;
}
static void deregister_case(uint32_t kind, unsigned registered, unsigned presence, unsigned found) {
    uint32_t ids[4] = {17,17,18,19}, kinds[4] = {kind,kind,kind,kind};
    registry_fixture f, decoy;
    build_registry(&f, 4, 3, kinds, ids);
    build_registry(&decoy, 0, 3, kinds, ids);
    uint32_t globals[2] = {0x1258a94, 0x1258a98};
    for (unsigned i = 0; i < 2; i++) {
        registry_fixture *selected = ((kind <= 0x1268) == (i == 1)) ? &f : &decoy;
        WORD(private_image, globals[i] - 0x400000) = (presence & (1u << i)) ? (uint32_t)(uintptr_t)selected->table : 0;
    }
    unsigned char subject[0x20], expected[0x20];
    memset(subject, 0x5a, sizeof subject);
    WORD(subject, 8) = kind; WORD(subject, 12) = found ? 17 : 20; subject[0x10] = (unsigned char)registered;
    memcpy(expected, subject, sizeof subject);
    unsigned active = presence == 3 && registered;
    current_registry = &f; registry_removed = active && found ? 0 : -1; registry_call_frees = 0;
    if (active) { WORD(expected, 8) = found ? 17 : 20; WORD(expected, 12) = 0xfffe; }
    unsigned result = invoke_registry_deregister(subject, private_image + 0x9c1650 - 0x400000);
    CHECK(result == active);
    CHECK(memcmp(subject, expected, sizeof subject) == 0);
    CHECK(registry_call_frees == (unsigned)(registry_removed >= 0));
    check_registry(&f, registry_removed, 1); check_registry(&decoy, -1, 0);
    CHECK(HeapValidate(fixture_heap, 0, NULL));
    printf("{\"kind\":\"case\",\"entry\":\"registry_deregister\",\"key_type\":%lu,\"registered\":%u,\"presence_mask\":%u,\"found\":%u,\"returned\":%u,\"original_heap_frees\":%u}\n",
           (unsigned long)kind, registered, presence, found, result, registry_call_frees);
    cleanup_registry(&f, registry_removed); cleanup_registry(&decoy, -1);
    registry_case_count++; case_count++;
}
static void insert_registry_case(uint32_t kind, unsigned active, unsigned presence, unsigned found) {
    uint32_t kinds[4] = {kind,kind,kind,kind}, ids[4] = {17,17,18,19};
    registry_fixture f, decoy;
    build_registry(&f, 4, 3, kinds, ids); build_registry(&decoy, 0, 3, kinds, ids);
    for (unsigned i = 0; i < 2; i++) {
        registry_fixture *selected = ((kind <= 0x1268) == (i == 1)) ? &f : &decoy;
        WORD(private_image, (i ? 0x1258a98 : 0x1258a94) - 0x400000) = (presence & (1u << i)) ? (uint32_t)(uintptr_t)selected->table : 0;
    }
    unsigned char subject[0x20], before[0x20];
    memset(subject, 0x5a, sizeof subject);
    WORD(subject, 8) = kind; WORD(subject, 12) = found ? 17 : 20; subject[0x10] = (unsigned char)active;
    memcpy(before, subject, sizeof subject);
    current_registry = &f; registry_removed = active && presence == 3 && found ? 0 : -1; registry_call_frees = 0;
    unsigned selected_present = (presence & (kind <= 0x1268 ? 2 : 1)) != 0;
    allocation_mode = 1; allocation_calls = 0; last_allocation = NULL;
    unsigned result = invoke_registry_insert(subject, private_image + 0x9c1590 - 0x400000);
    allocation_mode = 0;
    CHECK(result == selected_present && allocation_calls == selected_present);
    CHECK(registry_call_frees == (unsigned)(registry_removed >= 0));
    CHECK(memcmp(subject, before, sizeof subject) == 0); /* saved key restored; active byte not set */
    if (selected_present) { f.inserted_link = last_allocation; f.inserted_object = subject; }
    check_registry(&f, registry_removed, 1); check_registry(&decoy, -1, 0);
    CHECK(HeapValidate(fixture_heap, 0, NULL));
    printf("{\"kind\":\"case\",\"entry\":\"registry_insert\",\"key_type\":%lu,\"active\":%u,\"presence_mask\":%u,\"found\":%u,\"returned\":%u,\"original_heap_allocs\":%u,\"original_heap_frees\":%u}\n",
           (unsigned long)kind, active, presence, found, result, allocation_calls, registry_call_frees);
    cleanup_registry(&f, registry_removed); cleanup_registry(&decoy, -1);
    registry_case_count++; case_count++;
}

static uint32_t *integrated_table;
static void *integrated_node, *integrated_link;
static uint32_t integrated_kind, integrated_id;
static unsigned integrated_frees;
static BOOL record_integrated_pop_free(LPVOID pointer) {
    CHECK(active_bucket[2] == 1 && integrated_frees < 2);
    CHECK(integrated_table[1] == 1 && *(uint32_t *)(uintptr_t)integrated_table[2] == 0);
    if (integrated_frees == 0) {
        CHECK(pointer == integrated_link && integrated_table[0] == 1);
        CHECK(WORD(pointer, 0) == (uint32_t)(uintptr_t)integrated_node && WORD(pointer, 4) == 0);
        CHECK(memcmp(integrated_node, expected_target, sizeof expected_target) == 0);
    } else {
        CHECK(pointer == integrated_node && integrated_table[0] == 0);
        WORD(expected_target, 8) = integrated_id; WORD(expected_target, 12) = 0xfffe;
        CHECK(memcmp(pointer, expected_target, sizeof expected_target) == 0);
    }
    CHECK(HeapFree(fixture_heap, 0, pointer));
    integrated_frees++; total_frees++; snapshots++;
    return TRUE;
}
static void integrated_pop_case(uint32_t kind, unsigned automatic, uint16_t name_space, uint32_t seed) {
    registry_mode = 2;
        uint32_t heads[2] = {0,0}, tables[2][3] = {{0,1,0},{0,1,0}};
        for (unsigned i = 0; i < 2; i++) {
            tables[i][2] = (uint32_t)(uintptr_t)&heads[i];
            WORD(private_image, (i ? 0x1258a98 : 0x1258a94) - 0x400000) = (uint32_t)(uintptr_t)tables[i];
        }
        if (automatic) {
            *(uint16_t *)(private_image + 0x1258a90 - 0x400000) = name_space;
            WORD(private_image, 0x1258a9c - 0x400000) = seed;
            *(private_image + 0x131ca68 - 0x400000) = 0;
            CHECK(WORD(private_image, 0x1268fec - 0x400000) == 0 && WORD(private_image, 0x1268ff0 - 0x400000) == 0);
        }
        uint32_t counter_before = WORD(private_image, 0x1258a9c - 0x400000);
        integrated_kind = automatic ? (uint32_t)name_space + 0x1268 : kind;
        integrated_id = automatic ? seed + 1 : 17;
        integrated_frees = 0;
        integrated_table = tables[integrated_kind <= 0x1268 ? 1 : 0];
        integrated_node = allocate(0x288);
        WORD(integrated_node, 0) = (uint32_t)(uintptr_t)private_image + 0xe36428 - 0x400000;
        WORD(integrated_node, 0x28) = WORD(integrated_node, 0x240) = 15;
        uint32_t key[2] = {automatic ? 0 : integrated_kind, automatic ? 0 : integrated_id};
        uint32_t lookup_key[2] = {integrated_kind, integrated_id};
        uint32_t before_chain, after_chain;
        __asm__ __volatile__("movl %%fs:0, %0" : "=r"(before_chain));
        allocation_mode = 1; allocation_calls = 0; last_allocation = NULL;
        invoke_registry_initialize(integrated_node, key, private_image + 0x9c1390 - 0x400000);
        allocation_mode = 0;
        __asm__ __volatile__("movl %%fs:0, %0" : "=r"(after_chain));
        CHECK(before_chain == after_chain && allocation_calls == 1);
        integrated_link = last_allocation;
        CHECK(integrated_table[0] == 1 && *(uint32_t *)(uintptr_t)integrated_table[2] == (uint32_t)(uintptr_t)integrated_link);
        CHECK(WORD(integrated_link, 0) == (uint32_t)(uintptr_t)integrated_node && WORD(integrated_link, 4) == 0);
        CHECK(WORD(integrated_node, 8) == lookup_key[0] && WORD(integrated_node, 12) == lookup_key[1]);
        CHECK(key[0] == (automatic ? 0 : integrated_kind) && key[1] == (automatic ? 0 : integrated_id));
        CHECK(WORD(private_image, 0x1258a9c - 0x400000) == (automatic ? seed + 1 : counter_before));
        CHECK(*(private_image + 0x131ca68 - 0x400000) == 0);
        if (automatic) {
            CHECK(*(uint16_t *)(private_image + 0x1258a90 - 0x400000) == name_space);
            CHECK(*(uint16_t *)(private_image + 0x1258a92 - 0x400000) == 0);
        }
        CHECK(((unsigned char *)integrated_node)[0x10] == 1);
        CHECK(invoke_registry_lookup(lookup_key, integrated_table, private_image + 0x9c1d40 - 0x400000) == integrated_node);
        uint32_t bucket[4] = {(uint32_t)(uintptr_t)integrated_node,(uint32_t)(uintptr_t)integrated_node,1,0};
        active_bucket = bucket;
        memcpy(expected_target, integrated_node, sizeof expected_target);
        WORD(expected_target, 0) = (uint32_t)(uintptr_t)private_image + 0xe3a544 - 0x400000;
        CHECK(invoke_unlink(bucket, integrated_node, private_image + 0x4be8d0 - 0x400000) == 1);
        __asm__ __volatile__("movl %%fs:0, %0" : "=r"(after_chain));
        CHECK(before_chain == after_chain && integrated_frees == 2);
        CHECK(bucket[0] == 0 && bucket[1] == 0 && bucket[2] == 0);
        CHECK(invoke_registry_lookup(lookup_key, integrated_table, private_image + 0x9c1d40 - 0x400000) == NULL);
        unsigned opposite = integrated_kind <= 0x1268 ? 0 : 1;
        CHECK(tables[opposite][0] == 0 && heads[opposite] == 0);
        CHECK(HeapValidate(fixture_heap, 0, NULL));
        printf("{\"kind\":\"case\",\"entry\":\"%s\",\"key_type\":%lu,\"key_id\":%lu,\"namespace\":%u,\"seed\":%lu,\"original_heap_allocs\":%u,\"original_heap_frees\":%u}\n",
               automatic ? "automatic_pop_lifecycle" : "registered_pop_lifecycle",
               (unsigned long)integrated_kind, (unsigned long)integrated_id, (unsigned)name_space,
               (unsigned long)seed, allocation_calls, integrated_frees);
        registered_pop_case_count++; case_count++;
        if (automatic) automatic_id_case_count++;
    WORD(private_image, 0x1258a94 - 0x400000) = WORD(private_image, 0x1258a98 - 0x400000) = 0;
    registry_mode = 0;
}

static void run_integrated_pop_cases(void) {
    static const uint32_t types[] = {0,0x1268,0x1269,0x80000000,0xffffffff};
    for (unsigned t = 0; t < 5; t++) integrated_pop_case(types[t], 0, 0, 0);
    static const uint16_t spaces[] = {0,1,0x1268,0x7fff,0x8000,0xffff};
    static const uint32_t seeds[] = {0,17,0x7fffffff,0x80000000,0xfffffffe,0xffffffff};
    for (unsigned s = 0; s < 6; s++) for (unsigned i = 0; i < 6; i++) integrated_pop_case(0, 1, spaces[s], seeds[i]);
}

extern unsigned __cdecl invoke_original_lock(void *byte, void *entry);
__asm__(
    ".text\n"
    ".globl _invoke_original_lock\n"
    "_invoke_original_lock:\n"
    "movl 4(%esp), %eax\n"
    "call *8(%esp)\n"
    "ret\n"
);
static volatile LONG lock_worker_done;
static unsigned lock_worker_result;
static DWORD WINAPI lock_worker(LPVOID pointer) {
    lock_worker_result = invoke_original_lock(pointer, private_image + 0x9c12d0 - 0x400000);
    InterlockedExchange(&lock_worker_done, 1);
    return 0;
}
static void run_spinlock_cases(void) {
    volatile unsigned char *byte = private_image + 0x131ca68 - 0x400000;
    uint32_t counter = WORD(private_image, 0x1258a9c - 0x400000);
    for (unsigned initial_case = 0; initial_case < 3; initial_case++) {
        unsigned initial = initial_case == 2 ? 0x7f : initial_case;
        __atomic_store_n(byte, (unsigned char)initial, __ATOMIC_SEQ_CST);
        InterlockedExchange(&lock_yields, 0); InterlockedExchange(&lock_worker_done, 0);
        if (initial == 0) {
            CHECK(invoke_original_lock((void *)byte, private_image + 0x9c12d0 - 0x400000) == 0);
            CHECK(InterlockedCompareExchange(&lock_yields, 0, 0) == 0);
        } else {
            lock_yield_event = CreateEventA(NULL, TRUE, FALSE, NULL);
            CHECK(lock_yield_event != NULL);
            HANDLE worker = CreateThread(NULL, 0, lock_worker, (void *)byte, 0, NULL);
            CHECK(worker != NULL);
            CHECK(WaitForSingleObject(lock_yield_event, 5000) == WAIT_OBJECT_0);
            CHECK(InterlockedCompareExchange(&lock_worker_done, 0, 0) == 0);
            CHECK(__atomic_load_n(byte, __ATOMIC_SEQ_CST) == initial);
            __atomic_store_n(byte, 0, __ATOMIC_SEQ_CST); /* owner releases the isolated byte */
            CHECK(WaitForSingleObject(worker, 5000) == WAIT_OBJECT_0);
            CHECK(lock_worker_result == 0 && InterlockedCompareExchange(&lock_worker_done, 0, 0) == 1);
            CHECK(CloseHandle(worker)); CHECK(CloseHandle(lock_yield_event)); lock_yield_event = NULL;
        }
        CHECK(__atomic_load_n(byte, __ATOMIC_SEQ_CST) == 1);
        CHECK(WORD(private_image, 0x1258a9c - 0x400000) == counter);
        printf("{\"kind\":\"case\",\"entry\":\"spinlock_acquire\",\"initial_byte\":%u,\"yield_calls\":%lu,\"original_heap_allocs\":0,\"original_heap_frees\":0}\n",
               initial, (unsigned long)InterlockedCompareExchange(&lock_yields, 0, 0));
        __atomic_store_n(byte, 0, __ATOMIC_SEQ_CST);
        lock_case_count++; case_count++;
    }
}

static void run_registry_cases(void) {
    registry_mode = 1;
    static const unsigned counts[] = {0,1,5,16}, buckets[] = {1,3,7};
    uint32_t kinds[20] = {0,0,0x1268,0x1269,0xffffffff,0x80000000};
    uint32_t ids[20] = {0,0,17,18,0xffffffff,0};
    for (unsigned i = 6; i < 16; i++) { kinds[i] = i & 1 ? 0x1269 : 0x1268; ids[i] = 100+i; }
    for (unsigned i = 16; i < 20; i++) { kinds[i] = i == 18 ? 0x80000000 : i == 19 ? 0xffffffff : 0x1268+i-16; ids[i] = 0xfffffffe; }
    for (unsigned b = 0; b < 3; b++) for (unsigned c = 0; c < 4; c++) {
        for (unsigned q = 0; q < counts[c]; q++) direct_registry_case(counts[c], buckets[b], kinds[q], ids[q]);
        for (unsigned q = 16; q < 20; q++) direct_registry_case(counts[c], buckets[b], kinds[q], ids[q]);
    }
    static const uint32_t types[] = {0,0x1268,0x1269,0x80000000,0xffffffff};
    for (unsigned t = 0; t < 5; t++) for (unsigned registered = 0; registered < 2; registered++)
        for (unsigned presence = 0; presence < 4; presence++) for (unsigned found = 0; found < 2; found++)
            deregister_case(types[t], registered, presence, found);
    for (unsigned t = 0; t < 5; t++) for (unsigned active = 0; active < 2; active++)
        for (unsigned presence = 0; presence < 4; presence++) for (unsigned found = 0; found < 2; found++)
            insert_registry_case(types[t], active, presence, found);
    WORD(private_image, 0x1258a94 - 0x400000) = WORD(private_image, 0x1258a98 - 0x400000) = 0;
    registry_mode = 0;
}
