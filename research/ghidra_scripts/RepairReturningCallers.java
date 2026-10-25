// @category Victoria2
// Recover candidate flow after a refuted unconditional noreturn annotation.
// New bodies remain analyzer-derived, not semantically certified functions.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class RepairReturningCallers extends GhidraScript {
    private String quote(String value) { return "\"" + value.replace("\"", "\"\"") + "\""; }
    @Override public void run() throws Exception {
        if (!currentProgram.getExecutableSHA256().equalsIgnoreCase(
            "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))
            throw new IllegalStateException("Wrong binary profile");
        if (currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
            .getBoolean("Non-Returning Functions - Discovered", true))
            throw new IllegalStateException("Disable the reproduced heuristic false positive first");
        Function wrapper = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x00aae91bL));
        if (wrapper == null || wrapper.hasNoReturn()) throw new IllegalStateException("Wrapper still noreturn");
        Path out = Path.of(getScriptArgs()[0]); Files.createDirectories(out);
        Set<Address> functionEntries = new TreeSet<>();
        List<Address> callSites = new ArrayList<>();
        for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(wrapper.getEntryPoint()))
            if (ref.getReferenceType().isCall()) callSites.add(ref.getFromAddress());
        Collections.sort(callSites);
        int missing = 0, decoded = 0, noOwner = 0, externalOwner = 0, changed = 0, failed = 0;
        try (PrintWriter sites = new PrintWriter(Files.newBufferedWriter(out.resolve("fallthroughs.csv")))) {
            sites.println("call_va,next_va,owner_va,next_owner_va,missing_instruction_before,disassembly_requested,status");
            for (Address site : callSites) {
                monitor.checkCancelled();
                Instruction instruction = currentProgram.getListing().getInstructionAt(site);
                if (instruction == null) continue;
                if (instruction.getFlowOverride() != FlowOverride.NONE)
                    throw new IllegalStateException("Unexpected flow override at " + site);
                Address next = instruction.getMaxAddress().next();
                Function owner = currentProgram.getFunctionManager().getFunctionContaining(site);
                Function nextOwner = currentProgram.getFunctionManager().getFunctionContaining(next);
                boolean absent = currentProgram.getListing().getInstructionAt(next) == null;
                boolean requested = false;
                String status = "candidate_return_flow";
                if (owner == null) { noOwner++; status = "no_owner_manual_review"; }
                else if (nextOwner != null && !nextOwner.equals(owner)) {
                    externalOwner++; status = "other_function_manual_review";
                } else {
                    functionEntries.add(owner.getEntryPoint());
                    if (absent) {
                        missing++; requested = true;
                        disassemble(next);
                        if (currentProgram.getListing().getInstructionAt(next) != null) decoded++;
                        else status = "disassembly_inconclusive";
                    }
                }
                sites.println(site + "," + next + "," + (owner == null ? "" : owner.getEntryPoint()) + "," +
                    (nextOwner == null ? "" : nextOwner.getEntryPoint()) + "," + absent + "," + requested + "," + status);
            }
        }
        try (PrintWriter bodies = new PrintWriter(Files.newBufferedWriter(out.resolve("bodies.csv")))) {
            bodies.println("entry_va,body_before,body_after,fixup_returned,status");
            for (Address entry : functionEntries) {
                monitor.checkCancelled();
                Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
                if (function == null) continue;
                String before = function.getBody().toString();
                boolean result = CreateFunctionCmd.fixupFunctionBody(currentProgram, function, monitor);
                String after = function.getBody().toString();
                boolean differs = !before.equals(after);
                if (differs) changed++;
                if (!result && differs) failed++;
                bodies.println(entry + "," + quote(before) + "," + quote(after) + "," + result +
                    "," + (differs ? "changed_analyzer_candidate" : "unchanged_candidate"));
            }
        }
        Files.writeString(out.resolve("repair-summary.json"),
            "{\n  \"wrapper_call_sites\": " + callSites.size() +
            ",\n  \"missing_fallthrough_instructions\": " + missing +
            ",\n  \"decoded_fallthroughs\": " + decoded +
            ",\n  \"functions_considered\": " + functionEntries.size() +
            ",\n  \"function_bodies_changed\": " + changed +
            ",\n  \"no_owner_sites\": " + noOwner +
            ",\n  \"other_function_owner_sites\": " + externalOwner +
            ",\n  \"unexpected_changed_without_success\": " + failed +
            ",\n  \"semantics_confirmed\": false,\n  \"binary_patched\": false\n}\n");
        println("RETURN_FLOW_REPAIR: candidate_bodies_changed=" + changed + " recovered_instructions=" + decoded);
    }
}
