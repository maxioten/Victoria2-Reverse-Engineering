// @category Victoria2
// Partial operational views and bounded evidence. No function signatures applied.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;

public class AnnotatePopVectorCallers extends GhidraScript {
    @Override public void run() throws Exception {
        if(!currentProgram.getExecutableSHA256().equalsIgnoreCase("62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))throw new IllegalStateException("Wrong binary");
        CategoryPath cat=new CategoryPath("/V2RE_Evidence");
        StructureDataType country=new StructureDataType(cat,"CountryTransferQueuesView80_Candidate",0);
        country.add(new ArrayDataType(ByteDataType.dataType,0x20,1),"unmodeled_prefix",null);
        country.add(DWordDataType.dataType,"context_index_bits","Ctor candidate4F6A10 writes from its third argument; transfer compares against region+12c");
        country.add(new ArrayDataType(ByteDataType.dataType,0x10,1),"unmodeled_24_33",null);
        for(String prefix:new String[]{"first","second"}) {
            if(prefix.equals("second"))country.add(DWordDataType.dataType,"unmodeled_40_43",null);
            for(String field:new String[]{"begin","end","capacity"})country.add(new PointerDataType(null,4),prefix+"_"+field,"0x278-byte payloads in bounded wrapper paths");
        }
        StructureDataType province=new StructureDataType(cat,"ProvincePendingPopsView792_Candidate",0);
        province.add(new ArrayDataType(ByteDataType.dataType,0x128,1),"unmodeled_prefix",null);
        province.add(DWordDataType.dataType,"tag_bits_unclassified","Do not infer ID semantics; constructor writes0x2d2d2d");
        province.add(DWordDataType.dataType,"context_table_index_bits","Used through manager global12587E4 then array+4");
        province.add(new ArrayDataType(ByteDataType.dataType,0x1dc,1),"unmodeled_130_30b",null);
        for(String field:new String[]{"begin","end","capacity"})province.add(new PointerDataType(null,4),"pending_"+field,"Candidate staging container; not proof of global POP storage");
        if(country.getLength()!=80 || province.getLength()!=792)throw new IllegalStateException("Bad view size");
        currentProgram.getDataTypeManager().addDataType(country,DataTypeConflictHandler.REPLACE_HANDLER);
        currentProgram.getDataTypeManager().addDataType(province,DataTypeConflictHandler.REPLACE_HANDLER);
        long[] entries={0x4ba430L,0x4ba780L,0x5091a0L};
        String[] names={"RE_PopTransferViaRegionQueue_Candidate","RE_ApplyPendingPopTransfers_Candidate","RE_CountryPopPhase_Candidate"};
        String[] comments={
            "ECX=queue owner,stack args=(source,amount),RET8. Four calls in5091A0,two recursive calls; existing Ghidra direct refs only.324 complete Unicorn reuse-path fixtures: type+3d9 one skips recursive preprocessing;type+40 zero,optional resource null,copied vectors null. Selects first zero-size slot from owner+30c/+310,adjusts type,passes global manager12587E4->array+4 indexed by owner+12c into actual5345A0. Core args,whole64KiB,ABI,FS0 checked. Destination payload+64 retains source region,not queue owner in this domain. Queue interpretation inferred. Append/recursive/optional cleanup paths unexecuted. See POP-VECTOR-CALLERS.md.",
            "Stack arg=owner,RET4. Direct caller685F53 is before economy in bounded daily CFG. Reads owner+30c/+310 stride278.1080 native complete new-node consumers and1152 native complete compatible merges validate factory/initialization/size/balance/log/slot cleanup/final buckets under declared fixtures. Further305 full Unicorn consumers with1..6 candidates compare exact search trace,actual merge target and whole128KiB;447 no-match prefixes stop at4BAA33 before factory selector. Ordinary passes prioritize exact type/culture/religion,then equal type3c+culture,then same type+culture50;first eligible within each. All require limit=-1 or size<limit. First exact pass ignores type3d9,others require0. If source3d8 nonzero and region12c differ,only lower signed type3c with same culture/religion is tried,first eligible rather than minimum. Source cleanup/ABI/FS0 checked only on full returns. Further1536 complete native consumers execute post-search4BAA33 type choice and factory:source3d8zero keeps source;otherwise last catalog entry with real slot18true,type3d9zero,signed type3c below original source is kept.376 choices change type,1160 keep source;50 cases refute minimum-field choice.18432 independent original fragments verify virtual predicate order and EAX. Factory-internal4B8C80 preserves chosen type via false null-type predicate;Its true branch now has2178 isolated complete native entry calls with existing singleton and first-present requested/alternative row selection;Further960 direct factory/unlink cycles integrate changed choice (216 changes),payload/bucket/identity/destruction checked. Full consumer combining catalog choice with changed internal selector,optional/stats/other movement keys/live tick untested. See FACTORY-INTERNAL-SELECTOR.md. See POP-FACTORY-SELECTION.md. Queue interpretation inferred. See POP-SELECTION.md,POP-MERGE.md and POP-CONSUMER.md.",
            "Candidate country POP/update phase; entry called at685ED1 in bounded daily region. Recovered direct refs include957EA0 scheduled update and four4BA430 owner-queue calls;reads context vectors+34/+44. Country vtable DFFACC RTTI and ctor4F6A10 descriptor stores independently byte checked. This is not full execution or proof of all types/paths; local contexts and constructor stores are bounded evidence. Full world tick,exceptions,reentry and concurrency unproved. See POP-VECTOR-CALLERS.md."
        };
        String start="[V2RE vector callers 2026-10-21]",end="[End V2RE vector callers]";
        StringBuilder result=new StringBuilder("Two partial views; no signatures or live-memory types applied.\n");
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
        Path out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);Files.writeString(out.resolve("pop-vector-caller-contracts.txt"),result);
        println("POP_VECTOR_CALLERS_ANNOTATED: three bounded comments,two partial views;signatures unchanged");
    }
}
