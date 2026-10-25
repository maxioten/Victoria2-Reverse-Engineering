// @category Victoria2
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import java.io.*;
import java.nio.file.*;
import java.util.HexFormat;

public class QueryEvidence extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("Expected RVA and output directory");
        long rva = Long.decode(args[0]);
        Address at = currentProgram.getImageBase().add(rva);
        Path dir = Path.of(args[1]); Files.createDirectories(dir);
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(dir.resolve("query_" + Long.toHexString(rva) + ".txt")))) {
            out.println("sha256=" + currentProgram.getExecutableSHA256());
            out.println("RVA=" + Long.toHexString(rva) + " VA=" + at);
            out.println("External names and decompiler types are tentative.");
            for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(at))
                out.println("reference " + ref.getFromAddress() + " " + ref.getReferenceType());
            Instruction ins = currentProgram.getListing().getInstructionAt(at);
            for (int i = 0; i < 24 && ins != null; ++i, ins = ins.getNext())
                out.println(ins.getAddress() + " " + HexFormat.of().formatHex(ins.getBytes()) + " " + ins);
            Function function = currentProgram.getFunctionManager().getFunctionContaining(at);
            if (function != null) {
                out.println("function=" + function.getName() + " body=" + function.getBody());
                DecompInterface decompiler = new DecompInterface();
                try {
                    decompiler.openProgram(currentProgram);
                    DecompileResults result = decompiler.decompileFunction(function, 90, monitor);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null)
                        out.println(result.getDecompiledFunction().getC());
                    else out.println("INCONCLUSIVE: " + result.getErrorMessage());
                } finally { decompiler.dispose(); }
            } else out.println("INCONCLUSIVE: no function boundary at this address");
        }
    }
}
