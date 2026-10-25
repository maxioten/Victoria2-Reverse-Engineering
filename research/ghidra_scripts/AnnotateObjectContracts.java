// @category Victoria2
// Operational contracts with bounded evidence; no guessed C++ identities or calling conventions.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;

public class AnnotateObjectContracts extends GhidraScript {
    @Override public void run() throws Exception {
        if (!currentProgram.getExecutableSHA256().equalsIgnoreCase(
            "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))
            throw new IllegalStateException("Wrong binary profile");
        DataTypeManager manager = currentProgram.getDataTypeManager();
        CategoryPath category = new CategoryPath("/V2RE_Evidence");
        StructureDataType handle = new StructureDataType(category, "ObjectHandle12_Operational", 0);
        handle.add(new PointerDataType(null, 4), "resolved_pointer", "Refreshed by VA 00967F50; untouched by 00967F10");
        handle.add(DWordDataType.dataType, "type_bits", "Unsigned table selection at threshold 0x1268");
        handle.add(DWordDataType.dataType, "id_bits", "Full 32-bit key field");
        StructureDataType key = new StructureDataType(category, "ObjectKey8_Operational", 0);
        key.add(DWordDataType.dataType, "type_bits", "Hash shifts this field left by 16 bits");
        key.add(DWordDataType.dataType, "id_bits", "Added with 32-bit wrap before unsigned remainder");
        StructureDataType node = new StructureDataType(category, "RegistryChainNode8_Operational", 0);
        node.add(new PointerDataType(null, 4), "object", "Compared object fields at +8 and +0xc");
        node.add(new PointerDataType(node, 4), "next", "Null-terminated chain in tested domain");
        StructureDataType table = new StructureDataType(category, "RegistryHeader12_Operational", 0);
        table.add(DWordDataType.dataType, "entry_count_operational", "VA 009C1590 increments on insertion; 009C1CB0 decrements after key removal. Lookup does not read. Table constructor unverified.");
        table.add(DWordDataType.dataType, "bucket_count", "Positive unsigned divisor in tested domain");
        table.add(new PointerDataType(new PointerDataType(node, 4), 4), "bucket_heads", "Array of 32-bit node pointers");
        StructureDataType registration = new StructureDataType(category, "ObjectRegistrationView20_Operational", 0);
        registration.add(new ArrayDataType(ByteDataType.dataType, 8, 1), "unmodeled_prefix", "No class identity or total size inferred from this view");
        registration.add(DWordDataType.dataType, "type_bits", "Input key; overwritten with previous id by VA 009C1650 on active path");
        registration.add(DWordDataType.dataType, "id_bits", "Input key; overwritten with 0xFFFE on active path, including missing-key case");
        registration.add(ByteDataType.dataType, "active_byte", "VA 009C1390 writes one after insertion helper; checked by 009C1650 and not cleared by tested paths");
        registration.add(new ArrayDataType(ByteDataType.dataType, 3, 1), "unmodeled_tail", "Not asserted to be padding");
        if (handle.getLength() != 12 || key.getLength() != 8 || node.getLength() != 8 || table.getLength() != 12 || registration.getLength() != 20)
            throw new IllegalStateException("Unexpected datatype sizes");
        StringBuilder report = new StringBuilder("Pointer fields are explicitly 32-bit. No types applied to live memory or function signatures.\n");
        for (DataType type : new DataType[]{handle,key,node,table,registration}) {
            DataType added = manager.addDataType(type, DataTypeConflictHandler.REPLACE_HANDLER);
            report.append(added.getPathName()).append(" length=").append(added.getLength()).append('\n');
        }
        long[] entries = {0x009c1d40L,0x00967f50L,0x00967f10L,0x004be0f0L,0x004be8d0L,0x00955ae0L,
                          0x0068a900L,0x004be200L,0x009c1cb0L,0x009c1650L,0x009c1590L,0x009c1390L,0x009c12d0L};
        String[] names = {"RE_ObjectLookupByKey","RE_HandleRefresh","RE_HandleLookup",
                          "RE_PopDetach","RE_PopUnlinkOrMark","RE_PopDestroy_Candidate",
                          "RE_ReferenceUnlinkAndDelete_Candidate","RE_PointerVectorEraseFirst_Candidate",
                          "RE_RegistryRemoveFirstByKey","RE_ObjectDeregister_Candidate",
                          "RE_RegistryInsertObject","RE_ObjectInitializeRegistration_Candidate","RE_ByteLockAcquire"};
        String[] contracts = {
            "EAX=key pointer, ECX=table. Returns first exact-key object or NULL. Hash wraps to 32 bits. 684 synthetic queries; valid acyclic tables only.",
            "ESI=12-byte handle. Resolves using unsigned type threshold 0x1268, writes result to handle+0 and returns it. 32 fixtures for this and lookup variant. Additional216 native registered CPop copy/growth cycles confirm original-key resolution; after registered-source destruction/growth this variant returns zero and overwrites a stale cached address with zero. See POP-REGISTERED-IDENTITY.md.",
            "EAX=12-byte handle. Resolves and returns object; does not write the stored pointer. Same 32 fixtures, real lookup callee. Additional108 native registered-vector growth cases return zero for removed source key while retaining the old freed-array address in the handle cache; no stale-pointer dereference. See POP-REGISTERED-IDENTITY.md.",
            "EAX=node, ECX=bucket. Flag +0xc nonzero => no-op. Otherwise detaches, clears node links +0x278/+0x27c and decrements count. 88 full synthetic cases.",
            "ESI=bucket; first stack argument=node. Null => AL=0; flag +0xc nonzero => mark node+0x280. Immediate path relinks then destroys/frees and decrements count. Native PE32: 134 synthetic cases, 632 successful actual HeapFree calls, 192 complete pre-free snapshots; private relocated image, 0..3 CRegiment fixtures, absent registries. See NATIVE-POP.md for gates and limits.",
            "First stack argument=object; RET 4. Unicorn: nine empty-container fixtures and 36 nonfreeing virtual-wrapper fixtures. Native PE32 covers heap strings, buffers, optional-object cleanup and 0..3 RTTI-linked CRegiment fixtures via unlink. 134 synthetic list cases with explicit global-state gates and absent registries. CPop name linked by validated RTTI; effects remain bounded to declared fixtures.",
            "EAX=context; stack argument=object; RET 4. Can erase object from vector at object+0x30+0x3c, clear object+0x30, run external bookkeeping and invoke virtual slot zero with flag one. Native POP fixtures execute actual CRegiment destructor path with state+0xd1d=1,+0xd1c=0,object+0x74=0. Other branches and arbitrary runtime types unvalidated; no purity claim.",
            "EAX=three-word pointer-vector view; EDX=pointer to needle. Searches first equal 32-bit entry and calls 0x68f020. Native POP fixtures validate first-slot removal and overlapping shifts for 1..3 CRegiment references; arbitrary vector invariants and missing-element cases not dynamically covered here.",
            "EAX=two-dword key, first stack argument=table; RET 4. Removes first exact-key chain link, calls real free wrapper on link only, then decrements table+0. AL=1 on match, AL=0 on miss. 114 native fixtures, 66 real 8-byte link frees; referenced object bytes unchanged. Valid acyclic tables, positive bucket counts only.",
            "ESI=object; RET. Requires both registry globals nonnull and object+0x10 nonzero. Selects table using unsigned object+8 <= 0x1268, attempts key removal, then sets object+8=old object+0xc and object+0xc=0xfffe. Returns AL=1 EVEN IF KEY ABSENT; does not clear +0x10. 80 native fixtures including five active missing-key counterexamples. Not a general successful-removal predicate. Additional216 registered CPop copy/growth lifecycles execute successful removal through source destructor;108 growth cases verify unlink before old-array free and identity not reassigned to inactive copies. See POP-REGISTERED-IDENTITY.md.",
            "EAX=object; RET. Saves key, calls deregister if +0x10 is active, restores key, selects registry by unsigned type threshold and inserts an 8-byte link at bucket head using original allocator. Increments table+0. Does not set active byte. 80 native fixtures, 40 successful real allocations, five prior link frees. Allocation failure/exception paths not validated.",
            "ECX=object; stack argument=two-word key; RET 4. Outer registration layer checks existing key, may generate ID, calls 009C1590 and writes object+0x10=1. Native: five explicit-key plus 36 automatic-key empty-table POP lifecycles. Automatic type=zero-extended word at 01258A90+0x1268, id=wrapping increment at 01258A9C. Releases byte lock 0131CA68 BEFORE object key stores and table insertion. Additional216 explicit-key CPop copy/growth cycles use original insertion with types0/1268/1269/FFFFFFFF,high-bit IDs and1/3/7 buckets. Duplicate-key error,missing-table outer paths and parallel registry mutation untested. See POP-REGISTERED-IDENTITY.md.",
            "EAX=valid writable byte pointer; RET. LOCK CMPXCHG compares zero, writes one, retries with PAUSE and SwitchToThread on contention. Returns EAX=0 with byte held at one; does not release. Three native isolated tests: free byte, held 1 and held 0x7f; controlled worker resumes after owner release. No fairness or whole-registry thread-safety proof."
        };
        String marker = "[V2RE object contracts 2026-10-21]";
        for (int i=0; i<entries.length; i++) {
            Function function = currentProgram.getFunctionManager().getFunctionAt(toAddr(entries[i]));
            if (function == null) throw new IllegalStateException("Missing function " + Long.toHexString(entries[i]));
            String previous = function.getName();
            if (function.getSymbol().getSource() == SourceType.DEFAULT || previous.equals(names[i]))
                function.setName(names[i], SourceType.USER_DEFINED);
            String comment = function.getComment();
            if (comment != null && comment.contains("Class identity remains inferred.")) {
                comment = comment.replace("Class identity remains inferred.",
                    "CPop name linked by validated RTTI; effects remain bounded to declared fixtures.");
                function.setComment(comment);
            }
            String endMarker = "Names are operational; synthetic cases do not prove all inputs, lifetimes or concurrency.";
            String owned = marker + "\n" + contracts[i] +
                "\nEvidence: research/docs/contracts/OBJECT-REGISTRY.md, POP-SCHEDULE.md, POP-LIFETIME.md, NATIVE-POP.md, POP-REGIMENTS.md, REGISTRY-INSERTION.md, AUTOMATIC-IDS.md." +
                "\n" + endMarker;
            if (comment != null && comment.contains(marker)) {
                int start = comment.indexOf(marker);
                int end = comment.indexOf(endMarker, start);
                if (end < 0) throw new IllegalStateException("Incomplete owned comment at " + function.getEntryPoint());
                function.setComment(comment.substring(0, start) + owned + comment.substring(end + endMarker.length()));
            } else function.setComment((comment == null ? "" : comment + "\n") + owned);
            report.append(function.getEntryPoint()).append(' ').append(previous).append(" -> ")
                .append(function.getName()).append('\n');
        }
        Path out = Path.of(getScriptArgs()[0]); Files.createDirectories(out);
        Files.writeString(out.resolve("object-contracts.txt"), report);
        println("OBJECT_CONTRACTS_ANNOTATED: 5 minimal data layouts, 13 operational comments; signatures unchanged");
    }
}
