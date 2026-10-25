// @category Victoria2
// Structural candidate search only: matching displacements do not establish a shared type.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import java.io.*;
import java.nio.file.*;
import java.util.HexFormat;

public class FindFieldAccesses extends GhidraScript {
    private String quote(String value) { return "\"" + value.replace("\"", "\"\"") + "\""; }
    @Override public void run() throws Exception {
        String hash = currentProgram.getExecutableSHA256();
        if (!hash.equalsIgnoreCase("62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))
            throw new IllegalStateException("Wrong binary profile");
        long displacement = Long.decode(getScriptArgs()[0]);
        Path dir = Path.of(getScriptArgs()[1]); Files.createDirectories(dir);
        long matches = 0;
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(dir.resolve("field_" + Long.toHexString(displacement) + ".csv")))) {
            out.println("site_va,function_va,instruction,bytes,status");
            InstructionIterator all = currentProgram.getListing().getInstructions(true);
            while (all.hasNext() && !monitor.isCancelled()) {
                Instruction ins = all.next();
                boolean match = false;
                for (int op = 0; op < ins.getNumOperands(); op++) {
                    if (!ins.getDefaultOperandRepresentation(op).contains("[")) continue;
                    for (Object part : ins.getOpObjects(op))
                        if (part instanceof Scalar && ((Scalar)part).getUnsignedValue() == displacement) match = true;
                }
                if (!match) continue;
                Function f = currentProgram.getFunctionManager().getFunctionContaining(ins.getAddress());
                out.println(ins.getAddress() + "," + (f == null ? "" : f.getEntryPoint()) + "," +
                    quote(ins.toString()) + "," + HexFormat.of().formatHex(ins.getBytes()) + ",unattributed_field_candidate");
                matches++;
            }
        }
        Files.writeString(dir.resolve("field_" + Long.toHexString(displacement) + "_scope.txt"),
            "sha256=" + hash + "\npreferred_image_base=" + currentProgram.getImageBase() +
            "\nfield_displacement=" + Long.toHexString(displacement) + "\nmatching_instructions=" + matches +
            "\nscope=Ghidra-decoded instructions only; same displacement does not prove same object type\n");
        println("FIELD_ACCESS_CANDIDATES displacement=" + Long.toHexString(displacement) + " matches=" + matches);
    }
}
