// @category Victoria2
// Context windows are instruction-order evidence, not a proof of argument dataflow.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.HexFormat;

public class ExportCallContexts extends GhidraScript {
    @Override public void run() throws Exception {
        String hash=currentProgram.getExecutableSHA256();
        if (!hash.equalsIgnoreCase("62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))
            throw new IllegalStateException("Wrong binary profile");
        long rva=Long.decode(getScriptArgs()[0]);
        Address target=currentProgram.getImageBase().add(rva);
        Path dir=Path.of(getScriptArgs()[1]); Files.createDirectories(dir);
        List<Address> sites=new ArrayList<>();
        for (Reference ref:currentProgram.getReferenceManager().getReferencesTo(target))
            if (ref.getReferenceType().isCall()) sites.add(ref.getFromAddress());
        Collections.sort(sites);
        try (PrintWriter out=new PrintWriter(Files.newBufferedWriter(dir.resolve("callers_"+Long.toHexString(rva)+".txt")))) {
            out.println("sha256="+hash+" preferred_image_base="+currentProgram.getImageBase());
            out.println("target_RVA="+Long.toHexString(rva)+" target_VA="+target+" call_reference_candidates="+sites.size());
            out.println("Scope: existing Ghidra references and local instruction windows; no semantic naming or dataflow proof.");
            for (Address site:sites) {
                Function owner=currentProgram.getFunctionManager().getFunctionContaining(site);
                out.println("\nCALL_SITE="+site+" OWNER="+(owner==null?"unknown":owner.getEntryPoint()+" "+owner.getName()));
                Instruction at=currentProgram.getListing().getInstructionAt(site);
                if (at==null) { out.println("INCONCLUSIVE: no decoded instruction"); continue; }
                for (int i=0;i<12;i++) {
                    Instruction previous=at.getPrevious();
                    if (previous==null || (owner!=null && !owner.getBody().contains(previous.getAddress()))) break;
                    at=previous;
                }
                for (int i=0;i<20 && at!=null;i++,at=at.getNext()) {
                    if (owner!=null && !owner.getBody().contains(at.getAddress())) break;
                    out.println(at.getAddress()+" "+HexFormat.of().formatHex(at.getBytes())+" "+at);
                    if (at.getAddress().compareTo(site)>0 && i>=18) break;
                }
            }
        }
        println("CALL_CONTEXTS_EXPORTED sites="+sites.size()+" target="+target);
    }
}
