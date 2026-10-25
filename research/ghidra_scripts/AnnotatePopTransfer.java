// @category Victoria2
// Bounded transfer contracts. No signature installation or live memory typing.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;

public class AnnotatePopTransfer extends GhidraScript {
    @Override public void run() throws Exception {
        if (!currentProgram.getExecutableSHA256().equalsIgnoreCase(
            "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))
            throw new IllegalStateException("Wrong binary profile");
        CategoryPath category = new CategoryPath("/V2RE_Evidence");
        StructureDataType container = new StructureDataType(category,"TransferContainerView76_Operational",0);
        container.add(new ArrayDataType(ByteDataType.dataType,0x20,1),"unmodeled_prefix",null);
        container.add(DWordDataType.dataType,"context_id_bits","Compared with source region+0x12c by VA 005345A0");
        container.add(new ArrayDataType(ByteDataType.dataType,0x10,1),"unmodeled_24_33",null);
        container.add(new PointerDataType(null,4),"first_begin_candidate","Wrapper 00534810 scans objects at stride 0x278");
        container.add(new PointerDataType(null,4),"first_end_candidate",null);
        container.add(new ArrayDataType(ByteDataType.dataType,8,1),"unmodeled_3c_43",null);
        container.add(new PointerDataType(null,4),"second_begin_candidate","Wrapper 00534930 scans three-field matches");
        container.add(new PointerDataType(null,4),"second_end_candidate",null);
        StructureDataType balance = new StructureDataType(category,"PopTransferBalanceView392_Operational",0);
        balance.add(new ArrayDataType(ByteDataType.dataType,0x180,1),"unmodeled_prefix",null);
        balance.add(QWordDataType.dataType,"balance_bits","Operational 64-bit field; currency unit and full class layout unproved");
        if (container.getLength()!=76 || balance.getLength()!=392) throw new IllegalStateException("Unexpected view size");
        currentProgram.getDataTypeManager().addDataType(container,DataTypeConflictHandler.REPLACE_HANDLER);
        currentProgram.getDataTypeManager().addDataType(balance,DataTypeConflictHandler.REPLACE_HANDLER);
        long[] entries={0x005345a0L,0x00534810L,0x00534930L,0x00955f20L,0x00955a00L,0x00954f40L,0x00955450L,0x004beb50L};
        String[] names={"RE_PopTransferCore_Candidate","RE_PopTransferViaSlot34_Candidate",
                        "RE_PopTransferViaSlot44_Candidate","RE_PopSetRegion_Candidate","RE_PopInitializeFromSource_Candidate",
                        "RE_PopConstruct_Candidate","RE_PopCopyConstruct_Candidate","RE_PopVectorAppend_Candidate"};
        String[] comments={
            "EAX=source, stack args=(container,destination,amount,flag); RET 16. 1504 nonempty-destination plus 270 empty-destination Unicorn core fixtures, both type flags +0x40 zero; actual arithmetic, initialization/copy, size and region callees. Amount capped signed to source size, no lower-zero clamp. Event deltas use amount before size clamping. Share=ASR15(low64(trunc((amount<<30)/(sourceSize<<15))*sourceBalance)); balances wrap then clamp negative to zero. Allocation/other type paths untested. See POP-TRANSFER.md and POP-REUSE.md.",
            "Scans container+0x34 begin/end with 0x278-byte stride for first zero-size slot, adjusts its type and optional resource; otherwise creation/append path. Flag zero into core. 144 complete reuse-path fixtures plus 162 full append-path fixtures including original temporary construction/destruction and transfer with spare vector capacity, empty catalogs/distributions and existing singletons. Nonnull optional cleanup and heap/growth remain untested. EAX return unspecified. See POP-REUSE.md and POP-APPEND.md.",
            "Scans container+0x44 begin/end with 0x278-byte stride for first match on +0x68,+0x70,+0x6c; otherwise creation/append. Flag one into core. 288 matching fixtures plus 162 full append-path fixtures, with original temporary construction/destruction and transfer, spare capacity and empty catalogs/distributions. Matching field gameplay names and heap/growth remain partial. EAX return unspecified. See POP-REUSE.md and POP-APPEND.md.",
            "ESI=object, stack arg=new region; RET 4. Reached as real callee by bounded transfer fixtures with type+0x40 zero. Updates object+0x64 and can clear +0x274 when old/new nonnull contexts differ at +0x12c. Nonzero type flag reaches statistics/owner removal branches outside that tested domain. See POP-TRANSFER.md.",
            "ESI=destination, EDI=source; RET. Partial initialization: copies +0x6c,+0x70,+0x78,+0xa0,+0x128,+0x12c and four vectors through actual copy helpers; clears listed accumulator fields; writes 0x8000 to +0x130/+0x138. Not a full zero/reset: type +0x68, assigned +0x60, balance +0x180 and other bytes retained. 24 direct plus transfer/wrapper fixtures with sufficient capacities; old vector tails retained. No allocation or alias proof. See POP-REUSE.md.",
            "EDX=type, stack arg=destination; RET 4, EAX=destination. 72 direct and 324 wrapper emulated fixtures with empty catalogs, plus 384 native constructor/destructor cycles across catalog counts A/B 0/1/3/7, four cache-presence modes and optional resource off/on. Real eight/four-byte buffer allocation, zero data and catalog metadata, full payload/destructor checks. Pre-existing lazy singletons; 192 native cases set type+0x39c one and validate original 256-byte optional construction/two pools and free order. Not memset: preserves holes. Writes converted constant 3277 into qword +0x128 with CW037F; native host FX state restored. Caches F20C04/F20C08 preserved if nonzero, initialized if zero in tested domain. Optional resource copying, lazy singleton/error paths untested. See POP-CONSTRUCTION.md and POP-OPTIONAL.md.",
            "Stack args=(destination,source); RET 8, EAX=destination. 72 direct,126 append,324 wrapper fixtures with four empty distributions. Selective copy: +0x180 balance copied, +0x158..178 counters reset, identity taken from globals, refs/strings/optional resource reconstructed. Writes globals F20C04/F20C08 from 131BB34/12586DC; not pure or memcpy. Additional native evidence: 462 vector-growth cases; 336 have populated buffers, 216 have populated catalogs. Eight buffers copied deeply to logical capacities; four-byte metadata prefixes rebuilt from catalogs, logical surplus tails preserved. 5712 catalog words checked. 396 additional native copy/destructor cases start with source+1d4 nonnull;216 combine populated distribution buffers/catalogs: allocate256,construct both pools,assign only first pool;second pool and remaining fields retain destination construction.252 intermediate first-buffer frees checked;destination distributions deeply copied/metadata rebuilt,source and catalogs intact. Typed construction has separate384 native cycles including optional off/on. Additional108 native copies from actively registered sources retain source registration while destination stays inactive with global default key.108 registered-vector growth cases remove old source key without registering copies;handles do not rebind. Lazy singleton/errors untested. See POP-REGISTERED-IDENTITY.md and POP-OPTIONAL-COPY.md. See POP-APPEND.md, POP-GROWTH.md and POP-CATALOG-COPY.md.",
            "EDI=vector descriptor, ECX=source, RET, EAX=new element in tested domain. 126 direct fixtures cover external source or each aligned source slot within live range, 0/1/2/5/8 existing elements, spare capacity. Calls real 955450 copy constructor, end+=278; begin/capacity preserved. 324 wrapper fixtures additionally execute temporary constructor/destructor and core transfer. 4BEDE0 growth also validated in 462 native cases, 336 with populated internal buffers and 216 with populated catalogs; original successful real heap/copy/destruction. No live references or failure tests. See POP-APPEND.md and POP-GROWTH.md."
        };
        String start="[V2RE transfer contracts 2026-10-21]", end="[End V2RE transfer contracts]";
        StringBuilder report=new StringBuilder("Two partial views; no signatures or live memory types applied.\n");
        for(int i=0;i<entries.length;i++) {
            Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(entries[i]));
            if(f==null)throw new IllegalStateException("Missing function "+Long.toHexString(entries[i]));
            if(f.getSymbol().getSource()==SourceType.DEFAULT || f.getName().equals(names[i]))f.setName(names[i],SourceType.USER_DEFINED);
            String owned=start+"\n"+comments[i]+"\n"+end, previous=f.getComment();
            if(previous!=null && previous.contains(start)) {
                int a=previous.indexOf(start), b=previous.indexOf(end,a);
                if(b<0)throw new IllegalStateException("Incomplete owned annotation");
                f.setComment(previous.substring(0,a)+owned+previous.substring(b+end.length()));
            } else f.setComment((previous==null?"":previous+"\n")+owned);
            report.append(f.getEntryPoint()).append(' ').append(f.getName()).append('\n');
        }
        Path out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);
        Files.writeString(out.resolve("pop-transfer-contracts.txt"),report);
        println("POP_TRANSFER_ANNOTATED: eight bounded comments, two partial views; signatures unchanged");
    }
}
