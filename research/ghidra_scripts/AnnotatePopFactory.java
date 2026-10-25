// @category Victoria2
// Operational contracts for the tested factory path; no signatures installed.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;

public class AnnotatePopFactory extends GhidraScript {
    @Override public void run() throws Exception {
        if(!currentProgram.getExecutableSHA256().equalsIgnoreCase("62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))throw new IllegalStateException("Wrong binary");
        long[] entries={0x4b8d30L,0x4b8c80L,0x954a40L,0x96bb70L,0x955d90L};
        String[] names={"RE_CreateLinkedRegisteredPop_Candidate","RE_SelectFactoryPopType_Candidate","RE_PopConstructViaNullType_Candidate","RE_GetNullPopType_Candidate","RE_PopSetType_Candidate"};
        String[] comments={
            "Stack args=(owner,type),RET8,EAX=new node.1053 complete native factory/unlink cycles:selector4B8C80,temp ctor954A40,648-byte original allocation/copy955450,intrusive append to owner+194+type28*16,temp destruction,explicit key(2e,old F09568),virtual registration via CPop slot18->9C1390,set type955D90,region955F20. Counter stores old+1 before registration,32-bit wrap checked;generic1258A9C unchanged. Node whole648bytes,heads/tail/count,prior nodes,registry,handles,owner/types/catalogs and pre-free snapshots checked. 405 empty+648 populated catalog cycles;temporary and deep-copied distribution buffers checked before free,reverse vector order,node vectors freed before registry link;no optional resource/pre-existing singletons;Further1536 native full consumers choose last eligible catalog type before this factory and verify resulting type/bucket/node/identity/removal;real predicate vtables,see POP-FACTORY-SELECTION.md. 960 further full factory/unlink cycles integrate internal choice,216 changes/744 retained. Whole648byte selected-type payload,bucket0/1/2,identity,handle and pre-free snapshots checked with real heap. Empty distribution catalogs,type40/39c zero,existing singleton. Combined consumer catalog-choice plus changed internal selector/errors/concurrency untested;see FACTORY-INTERNAL-SELECTOR.md. Later1080 full consumer new-node paths validated with existing movement trees;later1152 full consumer merges into one existing compatible node also validated;other consumer paths untested,see POP-CONSUMER.md and POP-MERGE.md. See POP-FACTORY.md.",
            "Stack args=(requested type,owner),cdecl caller cleanup,EAX choice.2178 complete native entry calls with real CPopType/CNullPopType virtual slot18 on requested+3d4. False returns requested. True uses existing global1258728->array +owner58*B0+8 context;vector108/10c stride32,type at row+8. Returns first requested/alternative encountered,or requested for empty/no match. All ternary row sequences length0..4,owner index0/1/3,3 patterns;whole fixtures/EBX/ESI/EDI/EBP/FS0 checked,no original heap activity. Further960 full main factory/unlink cycles integrate choice,216 alternative changes verified in payload68 and bucket1/2 with registry/handle/destruction. Other five callers,lazy singleton and consumer combining catalog selection with changed choice untested. Six direct CALL refs byte checked,not exhaustive indirect callers. Predicate gameplay name unproved. See FACTORY-INTERNAL-SELECTOR.md.",
            "Stack arg=destination,RET4,EAX=destination. Reached as original temporary ctor in1053 native factory cycles. Obtains pre-existing type via96BB70/global1258A2C,unlike954F40 which receives type in EDX. Empty/populated catalogs,temporary buffers checked before original destruction,culture/religion singletons and caches preseeded;real FP conversion under CW037F. Final648-byte node and source metadata compared through actual copy ctor. Full constructor side effects under other globals/lazy init not proved. See POP-FACTORY.md.",
            "Returns global1258A2C if nonnull;1053 factory cycles use mapped CNullPopType fixture with original E36618 vtable. Full original getter executes that branch and restores FS0. Null branch allocates/constructs lazy type and is untested. See POP-FACTORY.md.",
            "EDI=pop,stack arg=requested type,RET4. Complete original callee reached by1053 factory cycles:current type is CNullPopType with real slot18 returning AL0,requested+39c zero,optional resource null. Final pop+68=requested type verified as part of entire648byte node before original unlink/destruction;then955F20 assigns owner region. Statistics removal/optional create/free branches outside this domain. See POP-FACTORY.md."
        };
        String start="[V2RE factory contracts 2026-10-21]",end="[End V2RE factory contracts]";
        StringBuilder result=new StringBuilder("Five bounded factory contracts; no signatures changed.\n");
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
        Path out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);Files.writeString(out.resolve("pop-factory-contracts.txt"),result);
        println("POP_FACTORY_ANNOTATED: five bounded comments;signatures unchanged");
    }
}
