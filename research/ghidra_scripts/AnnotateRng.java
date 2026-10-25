// @category Victoria2
// Operational names and comments only. No binary patches or guessed C signatures.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.util.HexFormat;

public class AnnotateRng extends GhidraScript {
    @Override public void run() throws Exception {
        String hash = "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648";
        if (!hash.equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("Wrong binary profile");
        long[] addresses = {0x009b7610L, 0x009b7670L, 0x009b7700L};
        String[] names = {"RE_RngNext_Signed32", "RE_RngInitialize_Signed32", "RE_RngRegenerate_Signed32"};
        String[] prefixes = {"56578bf8", "558bec83e4f8", "558bec83ec08"};
        String[] contracts = {
            "Input EAX=state; output EAX=tempered word; index at +0x9c0. Index zero regenerates before reading.",
            "Input EAX=seed, ECX=destination. Writes 624 words; tested index at +0x9c0 remains unchanged. Zero seed uses a global cache.",
            "Input EDI=state. In-place 624-word regeneration, arithmetic shifts and signed parity comparison; do not substitute generic MT19937."
        };
        String marker = "[V2RE signed RNG evidence 2026-10-21]";
        StringBuilder report = new StringBuilder("sha256=" + hash + "\nVA uses preferred base 00400000\n");
        for (int i = 0; i < addresses.length; i++) {
            byte[] expected = HexFormat.of().parseHex(prefixes[i]);
            byte[] observed = new byte[expected.length];
            currentProgram.getMemory().getBytes(toAddr(addresses[i]), observed);
            if (!java.util.Arrays.equals(expected, observed)) throw new IllegalStateException("Bytes differ");
            Function f = currentProgram.getFunctionManager().getFunctionAt(toAddr(addresses[i]));
            if (f == null) throw new IllegalStateException("Missing function boundary");
            String oldName = f.getName();
            if (f.getSymbol().getSource() == SourceType.DEFAULT || oldName.equals(names[i]))
                f.setName(names[i], SourceType.USER_DEFINED);
            String comment = f.getComment();
            if (comment == null || !comment.contains(marker))
                f.setComment((comment == null ? "" : comment + "\n") + marker + "\n" + contracts[i] +
                    "\nEvidence: research/docs/contracts/RNG.md; evidence/generated/rng/." +
                    "\nVerified: instruction subset and stated synthetic emulator cases. Not a universal equivalence proof." +
                    "\nNo standard calling convention or inferred parameter types installed.");
            report.append(f.getEntryPoint()).append(' ').append(oldName).append(" -> ")
                .append(f.getName()).append(" body=").append(f.getBody()).append('\n');
        }
        Function release = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x00aae91bL));
        if (release == null || release.hasNoReturn())
            throw new IllegalStateException("Previously refuted noreturn annotation is present");
        report.append("null_release_noreturn=false\nbinary_patched=false\n");
        Path dir = Path.of(getScriptArgs()[0]); Files.createDirectories(dir);
        Files.writeString(dir.resolve("rng-annotations.txt"), report);
        println("RNG_ANNOTATION_OK: 3 operational contracts, types unchanged");
    }
}
