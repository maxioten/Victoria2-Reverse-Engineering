// @category Victoria2
// Bounded contracts only; no recovered C++ signatures or live memory types.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;

public class AnnotatePopMerge extends GhidraScript {
    @Override public void run() throws Exception {
        if(!currentProgram.getExecutableSHA256().equalsIgnoreCase("62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))throw new IllegalStateException("Wrong binary");
        long[] entries={0x964370L,0x95a5f0L};
        String[] names={"RE_MergeWholePopIntoDestination_Candidate","RE_AddPopBalanceWithEvent_Operational"};
        String[] comments={
            "EDI=destination,stack=(source,flag),RET8.3780 complete Unicorn fixtures with actual size/integer/balance callees;source unchanged,whole64KiB/ABI/FS0 checked.1152 further full native4BA780 consumers merge one compatible existing node via4BA932,then original movement log/slot cleanup/final3-bucket scan;whole648byte destination/fixtures checked. Attribute+128/+12c=signed division of modular64 sum of low64((size<<15)*attribute) masked low15;zero summed size selects0.1530 fixtures refute unlimited-precision mean. Size clamps2m;previous size uses oldD unless0;flag0 skips size event,else index1/2 by region12c with rawS delta.95A5F0 adds raw source balance with event index2. Type40zero,optional null;Separate305 full Unicorn consumers validate multi-candidate search,including alternative lower-field and fallback passes;447 no-match prefixes stop before factory selection. Statistics/live world untested;see POP-SELECTION.md. See POP-MERGE.md.",
            "EAX=destination,ESI=balance event index,stack=source64delta,RET8. Reached by complete964370 with ESI2. If old balance nonnegative and delta positive and modular sum negative,saturatesINT64MAX;otherwise modular sum then clamp signed negative to0. Not symmetric saturation:MIN64+(-1) can wrapMAX64. Raw delta independently added modulo64 to+1d8+8*index and+218,even if final balance clamps/saturates.3780 whole merge fixtures plus1152 native full consumers;not all event indices/other callers/live money-unit semantics. See POP-MERGE.md."
        };
        String start="[V2RE POP merge 2026-10-21]",end="[End V2RE POP merge]";
        StringBuilder result=new StringBuilder("Two bounded comments; no signatures applied.\n");
        for(int i=0;i<entries.length;i++) {
            Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(entries[i]));
            if(f==null)throw new IllegalStateException("Missing function "+Long.toHexString(entries[i]));
            if(f.getSymbol().getSource()==SourceType.DEFAULT || f.getName().equals(names[i]))f.setName(names[i],SourceType.USER_DEFINED);
            String owned=start+"\n"+comments[i]+"\n"+end,old=f.getComment();
            if(old!=null && old.contains(start)) {
                int a=old.indexOf(start),b=old.indexOf(end,a);if(b<0)throw new IllegalStateException("Incomplete annotation");
                f.setComment(old.substring(0,a)+owned+old.substring(b+end.length()));
            } else f.setComment((old==null?"":old+"\n")+owned);
            result.append(f.getEntryPoint()).append(' ').append(f.getName()).append('\n');
        }
        Path out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);Files.writeString(out.resolve("pop-merge-contracts.txt"),result);
        println("POP_MERGE_ANNOTATED: two bounded comments;signatures unchanged");
    }
}
