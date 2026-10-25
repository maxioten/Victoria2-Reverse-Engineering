// @category Victoria2
// Prevent a reproduced heuristic false positive. Never patches binary memory.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.framework.options.Options;
import java.nio.file.*;

public class StabilizeReturningWrapper extends GhidraScript {
    @Override public void run() throws Exception {
        if (!currentProgram.getExecutableSHA256().equalsIgnoreCase(
            "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))
            throw new IllegalStateException("Wrong binary profile");
        Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        String analyzer = "Non-Returning Functions - Discovered";
        boolean oldOption = options.getBoolean(analyzer, true);
        setAnalysisOption(currentProgram, analyzer, "false");
        if (options.getBoolean(analyzer, true)) throw new IllegalStateException("Option was not applied");
        Function wrapper = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x00aae91bL));
        if (wrapper == null) throw new IllegalStateException("Missing wrapper");
        boolean oldNoReturn = wrapper.hasNoReturn();
        wrapper.setNoReturn(false);
        int cleared = 0;
        for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(wrapper.getEntryPoint())) {
            if (!ref.getReferenceType().isCall()) continue;
            Instruction ins = currentProgram.getListing().getInstructionAt(ref.getFromAddress());
            if (ins != null && ins.getFlowOverride() == FlowOverride.CALL_RETURN) {
                ins.setFlowOverride(FlowOverride.NONE); cleared++;
            }
        }
        Function unlink = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x004be8d0L));
        if (unlink == null) throw new IllegalStateException("Missing audited unlink candidate");
        String oldBody = unlink.getBody().toString();
        disassemble(toAddr(0x004be932L));
        Instruction ret = currentProgram.getListing().getInstructionAt(toAddr(0x004be93cL));
        if (ret == null || !ret.getMnemonicString().equals("RET"))
            throw new IllegalStateException("Audited RET not recovered");
        unlink.setBody(new AddressSet(toAddr(0x004be8d0L), toAddr(0x004be93eL)));
        Path out = Path.of(getScriptArgs()[0]); Files.createDirectories(out);
        Files.writeString(out.resolve("stabilization.txt"),
            "analyzer=" + analyzer + "\nanalyzer_before=" + oldOption + "\nanalyzer_after=false\n" +
            "wrapper_noreturn_before=" + oldNoReturn + "\nwrapper_noreturn_after=false\n" +
            "cleared_call_return_overrides=" + cleared + "\n" +
            "unlink_body_before=" + oldBody + "\nunlink_body_after=" + unlink.getBody() + "\n" +
            "basis=crt-null-release.json; pop-unlink evidence and audited original RET\n" +
            "other_function_bodies_not_certified=true\nbinary_patched=false\n");
        println("RETURNING_WRAPPER_STABILIZED; heuristic disabled for this project; unlink RET recovered");
    }
}
