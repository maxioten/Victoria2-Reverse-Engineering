// @category Victoria2
// One justified analysis correction, not a binary patch. Evidence: emulate_null_release.py.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import java.nio.file.*;

public class CorrectNullRelease extends GhidraScript {
    @Override public void run() throws Exception {
        if (!currentProgram.getExecutableSHA256().equalsIgnoreCase(
            "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))
            throw new IllegalStateException("Wrong binary profile");
        Function f = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x00aae91bL));
        if (f == null) throw new IllegalStateException("No function at candidate entry");
        boolean before = f.hasNoReturn();
        f.setNoReturn(false);
        long directCalls = 0, overrides = 0;
        StringBuilder callers = new StringBuilder("site_va,flow_override\n");
        for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint())) {
            if (!ref.getReferenceType().isCall()) continue;
            Instruction ins = currentProgram.getListing().getInstructionAt(ref.getFromAddress());
            if (ins == null) continue;
            directCalls++;
            callers.append(ins.getAddress()).append(',').append(ins.getFlowOverride()).append('\n');
            // Clear only the call-return override belonging to this now-refuted noreturn target.
            if (ins.getFlowOverride() == FlowOverride.CALL_RETURN) {
                ins.setFlowOverride(FlowOverride.NONE); overrides++;
            }
        }
        Path out = Path.of(getScriptArgs()[0]); Files.createDirectories(out);
        Files.writeString(out.resolve("null-release-callers.csv"), callers);
        Files.writeString(out.resolve("correction.txt"), "entry_va=00aae91b\nbefore_noreturn=" + before +
            "\nafter_noreturn=" + f.hasNoReturn() + "\ndirect_call_references=" + directCalls +
            "\ncleared_call_return_overrides=" + overrides +
            "\nbasis=crt-null-release.json; null argument counterexample only\nbinary_patched=false\n");
        println("NO_RETURN_CORRECTION before=" + before + " after=" + f.hasNoReturn() + " callers=" + directCalls);
    }
}
