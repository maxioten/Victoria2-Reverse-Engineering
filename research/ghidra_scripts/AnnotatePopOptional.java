// @category Victoria2
// Partial operational views only; no signatures or live-memory types applied.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;

public class AnnotatePopOptional extends GhidraScript {
    @Override public void run() throws Exception {
        if(!currentProgram.getExecutableSHA256().equalsIgnoreCase("62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))throw new IllegalStateException("Wrong binary");
        CategoryPath category=new CategoryPath("/V2RE_Evidence");
        StructureDataType pool=new StructureDataType(category,"GoodsPoolView88_Operational",0);
        pool.add(new PointerDataType(null,4),"vtable","RTTI link for preferred DFBDDC names CGoodsPool; not whole optional block identity");
        pool.add(DWordDataType.dataType,"class_word_bits","Initialized to 0x18d");
        pool.add(new ArrayDataType(ByteDataType.dataType,64,1),"index_bytes_candidate","Constructor zeros all 64 bytes; full runtime meaning unproved");
        pool.add(new PointerDataType(null,4),"values_begin",null);
        pool.add(new PointerDataType(null,4),"values_end",null);
        pool.add(new PointerDataType(null,4),"values_capacity",null);
        pool.add(new ArrayDataType(ByteDataType.dataType,4,1),"unmodeled_54_57","Preserved poison bytes in native constructor fixtures");
        DataType installed=currentProgram.getDataTypeManager().addDataType(pool,DataTypeConflictHandler.REPLACE_HANDLER);
        StructureDataType block=new StructureDataType(category,"PopOptionalBlock256_Operational",0);
        block.add(installed,"first_pool",null);block.add(installed,"second_pool",null);
        block.add(new ArrayDataType(ByteDataType.dataType,0x38,1),"partly_modeled_b0_e7",null);
        block.add(QWordDataType.dataType,"converted_constant_bits","Original B31C36 writes 16384 under CW037F; unit not assigned");
        block.add(new ArrayDataType(ByteDataType.dataType,0x10,1),"partly_modeled_f0_ff",null);
        if(pool.getLength()!=88 || block.getLength()!=256)throw new IllegalStateException("Bad view sizes");
        currentProgram.getDataTypeManager().addDataType(block,DataTypeConflictHandler.REPLACE_HANDLER);
        long[] entries={0x954910L,0x955d40L,0x423920L,0x47dbb0L,0x43a880L};
        String[] names={"RE_PopOptionalConstruct_Candidate","RE_PopOptionalDestroyAndFree_Candidate","RE_QwordVectorAppend_Candidate","RE_GoodsPoolAssign_Candidate","RE_QwordVectorResizeZero_Candidate"};
        String[] comments={
            "Stack arg=destination, RET4,EAX=destination. 192 full native typed-construction lifecycle cases with type+39c one, plus396 CPop copy/destructor sequences (216 combined with populated distributions/catalogs), execute this original constructor on a real 256-byte allocation. Two pools at 0/58: RTTI-linked CGoodsPool vtable DFBDDC, class word18d,64 zero bytes at+8, one qword vector entry from global125E448. Two real 8-byte vector allocations; holes preserved and full256bytes compared. Constant16384.5 ->16384 via B31C36 with CW037F at+E8. Whole optional-block original class name unproved. See POP-OPTIONAL.md.",
            "ESI=optional resource, RET. Original code frees second pool vector at+A0, clears its triple, then first at+48 and clears it, then frees the 256-byte resource. 588 native full lifecycle fixtures (192 typed construction,396 copy) verify pointer/order/buffer and whole-resource pre-free snapshots with real HeapFree. CPop destructor leaves its own +1D4 field as the freed address in tested destroyed payload; not a usable live pointer. Pool assignment has separate 540 emulated and 480 native cases; 396 full CPop optional-copy cases (216 combined) also verify first-pool assignment and second-pool/scalar reconstruction; errors remain untested. See POP-OPTIONAL.md and GOODS-POOL-COPY.md.",
            "EDI=qword-vector descriptor,EAX=source qword. Original append reached twice per optional-resource constructor in 192 native cycles: empty/null descriptor grows to capacity1, copies exactly global125E448 8 bytes, end+=8. Actual allocator callees, no fabricated results. Tests cover zero/0123456789ABCDEF/FFFFFFFFFFFFFFFF qword values. This does not validate all alias, growth or failure branches. See POP-OPTIONAL.md.",
            "Stack args=(destination,source); RET8,EAX=destination. 540 complete Unicorn fixtures,108 same-object;480 direct native fixtures including132 real heap growths/84 old-buffer frees,plus396 full CPop optional-copy sequences including216 with populated distributions/catalogs. Copies global12587F4 bytes from source+8 to destination+8 (tested0..64), resizes vector+48 to source count, then copies qwords from index1. Index0 is retained if previously active, zero if resize creates it;360 fixtures refute full-vector literal-copy model. Full buffers/payload/source, tails, ABI and pre-free snapshots checked. In the parent CPop copy,only first pool assigned;second pool/scalars stay constructed. No partial overlap,errors or live-world proof. See POP-OPTIONAL-COPY.md. See GOODS-POOL-COPY.md.",
            "EDI=vector descriptor,EAX=new count,RET. Reached by original CGoodsPool assignment in540 emulated,480 direct native and396 full CPop optional-copy cases including216 with populated distributions/catalogs. Shrink updates end without clearing tail;grow zero-fills new logical qwords after ensuring capacity. Existing first element preserved. Native capacity6/count7 grows to9;unused tail remains allocator poison. Allocator/copy/free callees original. No arbitrary alias, large-count/error or concurrency proof. See GOODS-POOL-COPY.md."
        };
        String start="[V2RE optional contracts 2026-10-21]",end="[End V2RE optional contracts]";
        StringBuilder result=new StringBuilder("Two partial operational views, no applied live types or signatures.\n");
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
        Path out=Path.of(getScriptArgs()[0]);Files.createDirectories(out);Files.writeString(out.resolve("pop-optional-contracts.txt"),result);
        println("POP_OPTIONAL_ANNOTATED: five bounded comments, two partial views; signatures unchanged");
    }
}
