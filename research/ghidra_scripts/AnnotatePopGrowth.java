// @category Victoria2
// Bounded growth evidence; no signature or live-memory typing changes.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;

public class AnnotatePopGrowth extends GhidraScript {
    @Override public void run() throws Exception {
        if(!currentProgram.getExecutableSHA256().equalsIgnoreCase("62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))throw new IllegalStateException("Wrong binary");
        long[] entries={0x4bede0L,0x4bf200L,0x4bf4c0L,0x4c0af0L,0x4be400L};
        String[] names={"RE_PopVectorEnsureOneMore_Candidate","RE_PopVectorReserve_Candidate","RE_PopArrayAllocate_Candidate","RE_PopRangeCopyConstruct_Candidate","RE_PopRangeDestroy_Candidate"};
        String[] comments={
            "ECX=descriptor. Original capacity selection executed in 584 bounded fixtures, stopping before reserve/length-error call. For aligned positive tested spans: if size+1 exceeds capacity, reserve max(size+1,capacity+floor(capacity/2)), with coded limit checks. Pointer spans use 32-bit subtraction and signed division by 632. 462 complete native append/growth cases with full prior capacity and unregistered objects; 120 have eight buffers with empty catalogs and 216 have populated catalogs and source logical surplus 0/2. Additional108 registered-source vector-growth cases remove the old registry key while copied elements remain inactive/default-key;fresh handle lookup returns zero,not new element. Synthetic fixture does not prove this vector is the live world POP store. See POP-REGISTERED-IDENTITY.md and POP-GROWTH.md.",
            "ECX=descriptor, stack arg=requested capacity; RET 4. 462 complete native growth cases: allocates, copy-constructs old range, virtually destroys old elements with flag zero, frees old array, then publishes new descriptor. Deep copies/logical capacities/ordered frees checked; 216 populated-catalog cases verify metadata prefix reconstruction. Not memcpy: original 955450 resets counters/references and writes global caches. Pre-free old snapshots and full new allocation compared. Additional108 registered-source growth cases remove old identity during destruction;handles are not reassigned to copies. Arbitrary live reference graphs,heap failures and exceptions untested. See POP-REGISTERED-IDENTITY.md. Typed construction has separate 192 native lifecycle cases; see POP-CONSTRUCTION.md. See POP-GROWTH.md.",
            "ECX=count, EAX=allocated array in successful tested cases. Multiplies count by 0x278, calls original CRT new then real HeapAlloc. Encoded upper bound 0x67b23a is not proof of allocatable/live capacity. 570 successful outer-array native allocations (462 unregistered,108 registered-source), plus original internal-buffer reservations; declared poison initialization after allocation only. Failure/exception path untested. See POP-GROWTH.md.",
            "ECX=source begin, stack args include source end and destination begin; original normal loop calls 955450 for each 0x278-byte source. Reached by 462 complete native growth cases; 336 have eight buffers. Copy construction rebuilds four-byte metadata prefixes from catalog A entry+8 and B entry+30; source logical tails retained when catalogs shorter. 5712 metadata words checked. Destination copies allocate logical sizes only. See also POP-CATALOG-COPY.md. Exception cleanup shown statically but not executed. Not a bitwise relocation. See POP-GROWTH.md.",
            "EAX=begin, EDI=end; loops at stride 0x278 and calls each original virtual destructor with flag zero. Reached by complete native growth with null optional resource and absent registries; 336 populated-buffer cases verify per-element free order 104,F4,DC,CC,B4,A4,8C,7C including nonnull empty ranges. Old array bytes compared before HeapFree; original descriptor still present then. Additional108 native registered-source growth cases execute source deregistration and link free before array free. Optional-resource range destruction and arbitrary live reference graphs remain unproved. See POP-REGISTERED-IDENTITY.md. See POP-GROWTH.md."
        };
        String start="[V2RE growth contracts 2026-10-21]",end="[End V2RE growth contracts]";
        StringBuilder result=new StringBuilder();
        for(int i=0;i<entries.length;i++) {
            Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(entries[i]));
            if(f==null)throw new IllegalStateException("Missing function "+Long.toHexString(entries[i]));
            if(f.getSymbol().getSource()==SourceType.DEFAULT || f.getName().equals(names[i]))f.setName(names[i],SourceType.USER_DEFINED);
            String owned=start+"\n"+comments[i]+"\n"+end,old=f.getComment();
            if(old!=null && old.contains(start)) {
                int a=old.indexOf(start),b=old.indexOf(end,a);
                if(b<0)throw new IllegalStateException("Incomplete annotation");
                f.setComment(old.substring(0,a)+owned+old.substring(b+end.length()));
            } else f.setComment((old==null?"":old+"\n")+owned);
            result.append(f.getEntryPoint()).append(' ').append(f.getName()).append('\n');
        }
        Path out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);Files.writeString(out.resolve("pop-growth-contracts.txt"),result);
        println("POP_GROWTH_ANNOTATED: five bounded comments; signatures unchanged");
    }
}
