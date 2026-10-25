// @category Victoria2
// Bounded evidence for scheduled update and original size-setting entry.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;

public class AnnotatePopUpdate extends GhidraScript {
    @Override public void run() throws Exception {
        if (!currentProgram.getExecutableSHA256().equalsIgnoreCase(
            "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))
            throw new IllegalStateException("Wrong binary profile");
        StructureDataType view = new StructureDataType(new CategoryPath("/V2RE_Evidence"), "PopSizeView108_Operational", 0);
        view.add(new ArrayDataType(ByteDataType.dataType, 0x58, 1), "unmodeled_prefix", "No complete class layout inferred");
        view.add(DWordDataType.dataType, "current_size_bits", "Set by VA 00955FD0 to signed clamp [0,2000000]");
        view.add(DWordDataType.dataType, "previous_size_bits", "Old current size, except old zero selects new size");
        view.add(DWordDataType.dataType, "assigned_count_candidate", "Written directly if type flag +0x40 is zero; otherwise adjusted through statistics helpers on decrease");
        view.add(new PointerDataType(null, 4), "region_context_candidate", "VA 00955FD0 reads +0x58 index and +0x188 owner from this pointed region");
        view.add(new PointerDataType(null, 4), "type_context_candidate", "Flag +0x40 and index +0x28 in tested routes");
        if (view.getLength() != 108) throw new IllegalStateException("Unexpected view size");
        currentProgram.getDataTypeManager().addDataType(view, DataTypeConflictHandler.REPLACE_HANDLER);
        long[] entries = {0x00957ea0L, 0x00955fd0L,0x00b31c00L,0x00b31c36L};
        String[] names = {"RE_ScheduledPopUpdate_Candidate", "RE_PopSetSize_Operational",
                          "RE_X87Conversion_Dispatch_Candidate","RE_X87ToInt64_Masked_Candidate"};
        String[] comments = {
            "ECX=object, RET 8. Reached by country date/modulo selection. Bounded normal-return CFG: 1147 instructions, 3912 bytes, 71 CALL sites (six indirect). Calls opaque, exceptions and path feasibility unmodeled. Includes x87-to-integer helpers B31C00/B31C36, not evidence of RNG calls at those sites. No whole-update emulation, pure-function or parallel-safety proof; see POP-UPDATE.md.",
            "EAX=requested signed32 size, ESI=object, RET. Clamp [0,2000000]; store +0x58 and cache old size at +0x5c, except old zero caches new size. Type +0x40 zero writes +0x60 directly. Otherwise decreasing below +0x60 reaches actual statistics helpers. 1362 full original-entry Unicorn fixtures, 42 with existing positive-remainder map/vector rows; no allocation or erase. Whole 64KiB fixture arena compared. No real-game invariants or nonempty owner hierarchy proved; see POP-SIZE.md.",
            "Input ST(0), RET. Selector at preferred VA 013F3BE0 nonzero uses FSTP binary64 + CVTTSD2SI to EAX32; EDX stayed at incoming sentinel. Selector zero jumps to B31C36 returning EDX:EAX64. 3360 native observations: 56 binary64 + 84 canonical extended80 patterns, three entries, selector 0/1, four matched rounding controls. FSTP quantization creates in-signed32 differences: 1-2^-64 gives fast 1 vs fallback 0 in nearest mode. See FLOAT-CONVERSION.md; no C signature installed.",
            "Input ST(0), RET. FISTP signed64 with current rounding, then correction; zero and INT64_MIN shortcut bypasses correction. Native extended80 -2^63+0.5 returns INT64_MIN in nearest/down modes despite mathematical truncation fitting signed64. Positive 2^63-0.5 can overflow intermediate FISTP in nearest/up. Not unconditional truncation. 3360 bounded observations, precision-control 64-bit, masked exceptions, four matched rounding modes; CW preserved and x87 stack empty. All encodings, unmasked exceptions and other precision controls unverified. See FLOAT-CONVERSION.md."
        };
        String marker = "[V2RE scheduled POP contracts 2026-10-21]";
        String endMarker = "[End V2RE scheduled POP contracts]";
        StringBuilder report = new StringBuilder("Minimal view only; no live memory types or function signatures applied.\n");
        for (int i=0; i<entries.length; i++) {
            Function function = currentProgram.getFunctionManager().getFunctionAt(toAddr(entries[i]));
            if (function == null) throw new IllegalStateException("Missing function at " + Long.toHexString(entries[i]));
            if (function.getSymbol().getSource() == SourceType.DEFAULT || function.getName().equals(names[i]))
                function.setName(names[i], SourceType.USER_DEFINED);
            String owned = marker + "\n" + comments[i] + "\n" + endMarker;
            String old = function.getComment();
            if (old != null && old.contains(marker)) {
                int start=old.indexOf(marker), end=old.indexOf(endMarker, start);
                if (end < 0) throw new IllegalStateException("Incomplete annotation block");
                function.setComment(old.substring(0,start)+owned+old.substring(end+endMarker.length()));
            } else function.setComment((old==null?"":old+"\n")+owned);
            report.append(function.getEntryPoint()).append(' ').append(function.getName()).append('\n');
        }
        Path out = Path.of(getScriptArgs()[0]); Files.createDirectories(out);
        Files.writeString(out.resolve("pop-update-contracts.txt"), report);
        println("POP_UPDATE_ANNOTATED: four operational comments, one 108-byte partial view; signatures unchanged");
    }
}
