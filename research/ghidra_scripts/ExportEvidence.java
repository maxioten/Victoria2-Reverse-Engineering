// Export machine-derived facts and tentative decompiler output. No semantic renaming.
// @category Victoria2
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.HexFormat;

public class ExportEvidence extends GhidraScript {
    private String quote(String s) { return "\"" + s.replace("\"", "\"\"") + "\""; }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected output directory");
        Path dir = Path.of(args[0]);
        Files.createDirectories(dir);
        long functions = 0, calls = 0;
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(dir.resolve("functions.csv"), StandardCharsets.UTF_8))) {
            out.println("entry_va,end_va,body_bytes,name,signature,source,name_source,signature_source");
            FunctionIterator all = currentProgram.getFunctionManager().getFunctions(true);
            while (all.hasNext() && !monitor.isCancelled()) {
                Function f = all.next(); functions++;
                out.println(f.getEntryPoint() + "," + f.getBody().getMaxAddress() + "," +
                            f.getBody().getNumAddresses() + "," + quote(f.getName()) + "," +
                            quote(f.getSignature().toString()) + ",ghidra_project," +
                            f.getSymbol().getSource() + "," + f.getSignatureSource());
            }
        }
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(dir.resolve("calls.csv"), StandardCharsets.UTF_8))) {
            out.println("site_va,target_va,reference_type,instruction,bytes");
            InstructionIterator all = currentProgram.getListing().getInstructions(true);
            while (all.hasNext() && !monitor.isCancelled()) {
                Instruction ins = all.next();
                for (Reference r : ins.getReferencesFrom()) if (r.getReferenceType().isCall()) {
                    calls++;
                    out.println(ins.getAddress() + "," + r.getToAddress() + "," + r.getReferenceType() + "," +
                                quote(ins.toString()) + "," + HexFormat.of().formatHex(ins.getBytes()));
                }
            }
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            long[] candidates = {0x00654d80L, 0x00682ec0L, 0x006859c0L, 0x00489990L, 0x0051fd10L};
            for (long address : candidates) {
                Function f = currentProgram.getFunctionManager().getFunctionAt(toAddr(address));
                if (f == null) { println("No function at candidate " + Long.toHexString(address)); continue; }
                DecompileResults result = decompiler.decompileFunction(f, 90, monitor);
                Path output = dir.resolve("candidate_" + Long.toHexString(address) + ".c");
                String content = result.decompileCompleted() && result.getDecompiledFunction() != null
                    ? "/* TOOL OUTPUT: inferred C, not original source; names/types require validation. */\n" + result.getDecompiledFunction().getC()
                    : "/* DECOMPILATION FAILED: " + result.getErrorMessage() + " */\n";
                Files.writeString(output, content, StandardCharsets.UTF_8);
            }
        } finally { decompiler.dispose(); }
        Files.writeString(dir.resolve("export.txt"), "binary_sha256=" + currentProgram.getExecutableSHA256() +
            "\nlanguage=" + currentProgram.getLanguageID() + "\ncompiler=" + currentProgram.getCompilerSpec().getCompilerSpecID() +
            "\nfunctions=" + functions + "\ncall_references=" + calls + "\nsemantics_confirmed=false\n");
        println("V2_EVIDENCE_EXPORT_OK functions=" + functions + " call_references=" + calls);
    }
}
