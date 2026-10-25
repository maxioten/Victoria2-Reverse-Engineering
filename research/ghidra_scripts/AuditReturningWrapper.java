// @category Victoria2
// Read-only audit, including a saved-project reopen after stabilization.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import java.nio.file.*;

public class AuditReturningWrapper extends GhidraScript {
    @Override public void run() throws Exception {
        if (!currentProgram.getExecutableSHA256().equalsIgnoreCase(
            "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))
            throw new IllegalStateException("Wrong binary profile");
        boolean enabled = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
            .getBoolean("Non-Returning Functions - Discovered", true);
        Function wrapper = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x00aae91bL));
        if (wrapper == null) throw new IllegalStateException("Missing wrapper");
        int calls = 0, overrides = 0;
        for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(wrapper.getEntryPoint())) {
            if (!ref.getReferenceType().isCall()) continue;
            calls++;
            Instruction ins = currentProgram.getListing().getInstructionAt(ref.getFromAddress());
            if (ins != null && ins.getFlowOverride() == FlowOverride.CALL_RETURN) overrides++;
        }
        Function unlink = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x004be8d0L));
        boolean bodyContainsReturn = unlink != null && unlink.getBody().contains(toAddr(0x004be93eL));
        Path out = Path.of(getScriptArgs()[0]); Files.createDirectories(out);
        boolean pass = !enabled && !wrapper.hasNoReturn() && overrides == 0 && bodyContainsReturn;
        Files.writeString(out.resolve("saved-project-audit.json"),
            "{\n  \"pass\": " + pass + ",\n  \"heuristic_enabled\": " + enabled +
            ",\n  \"wrapper_noreturn\": " + wrapper.hasNoReturn() + ",\n  \"wrapper_call_references\": " + calls +
            ",\n  \"call_return_overrides\": " + overrides +
            ",\n  \"unlink_body_contains_return\": " + bodyContainsReturn +
            ",\n  \"scope\": \"Saved Ghidra metadata only; not global function-body correctness\"\n}\n");
        if (!pass) throw new IllegalStateException("Saved-project metadata regressed");
        println("SAVED_PROJECT_AUDIT_PASS: heuristic off, wrapper returns, no call-return overrides, unlink RET in body");
    }
}
