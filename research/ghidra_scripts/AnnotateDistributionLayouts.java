// @category Victoria2
// Minimal views and observed allocation spans, not recovered complete C++ declarations.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;

public class AnnotateDistributionLayouts extends GhidraScript {
    @Override public void run() throws Exception {
        if (!currentProgram.getExecutableSHA256().equalsIgnoreCase(
            "62d48c204364dd706584777c2e2b3c7ab3c5f1dd0170872554943575d53d6648"))
            throw new IllegalStateException("Wrong binary profile");
        CategoryPath category=new CategoryPath("/V2RE_Evidence");
        DataTypeManager manager=currentProgram.getDataTypeManager();
        StructureDataType view=new StructureDataType(category,"DistributionDataView16",0);
        view.add(DWordDataType.dataType,"word0_unread","Not read by the normalization routine");
        view.add(DWordDataType.dataType,"word4_unread","Not read by the normalization routine");
        view.add(new PointerDataType(LongLongDataType.dataType,4),"begin","64-bit bit-pattern slots; slot 0 excluded");
        view.add(new PointerDataType(LongLongDataType.dataType,4),"end","One past the last slot in the valid tested domain");
        view.setDescription("Minimal prefix consumed by VA 004BE780. This is not the full CDataSpread class layout.");
        StructureDataType payload=new StructureDataType(category,"CPopPayloadPrefix632_Candidate",0);
        payload.add(new PointerDataType(null,4),"vtable_pointer","CPop table identified by RTTI; lifetime changes this value");
        payload.add(new ArrayDataType(Undefined1DataType.dataType,628,1),"unreconstructed_payload","Unknown here; do not infer field semantics");
        payload.setDescription("Observed contiguous destruction stride 0x278, matching last copied dword +0x274. C++ sizeof interpretation remains inferred.");
        StructureDataType node=new StructureDataType(category,"PopListAllocation648_Operational",0);
        node.add(payload,"payload_prefix","CPop prefix at allocation offset zero");
        node.add(new PointerDataType(null,4),"previous","Written at +0x278 after payload copy");
        node.add(new PointerDataType(null,4),"next","Written at +0x27c");
        node.add(ByteDataType.dataType,"pending_mark","Written at +0x280; consumer not yet identified");
        node.add(new ArrayDataType(Undefined1DataType.dataType,7,1),"unknown_trailing_bytes","Do not assume these are all padding");
        if (view.getLength()!=16 || payload.getLength()!=632 || node.getLength()!=648)
            throw new IllegalStateException("Unexpected data-view size");
        StringBuilder report=new StringBuilder("No data types applied to live memory or signatures.\n");
        for (DataType type:new DataType[]{view,payload,node}) {
            DataType added=manager.addDataType(type,DataTypeConflictHandler.REPLACE_HANDLER);
            report.append(added.getPathName()).append(" length=").append(added.getLength()).append('\n');
        }
        Function function=currentProgram.getFunctionManager().getFunctionAt(toAddr(0x004be780L));
        if (function==null) throw new IllegalStateException("Missing normalization candidate");
        if (function.getSymbol().getSource()==SourceType.DEFAULT || function.getName().equals("RE_DistributionNormalize_100_15"))
            function.setName("RE_DistributionNormalize_100_15",SourceType.USER_DEFINED);
        String marker="[V2RE distribution 2026-10-21]";
        String comment=function.getComment();
        if (comment==null || !comment.contains(marker))
            function.setComment((comment==null?"":comment+"\n")+marker+
                "\nFirst stack argument=descriptor; data begin at +8, end at +0xc, 64-bit slots. Slot 0 unchanged."+
                "\n525 complete synthetic cases with original arithmetic helpers. Modular products and final ADC flags matter."+
                "\nDo not replace guard with signed sum>0 for all bit patterns. No concurrency or universal equivalence proof."+
                "\nEvidence: research/docs/contracts/DISTRIBUTION.md and RTTI.md; generated/distribution and rtti.");
        Path out=Path.of(getScriptArgs()[0]); Files.createDirectories(out);
        report.append(function.getEntryPoint()).append(' ').append(function.getName()).append('\n');
        Files.writeString(out.resolve("distribution-layouts.txt"),report);
        println("DISTRIBUTION_LAYOUTS_ANNOTATED: minimal view, payload-stride candidate and allocation span");
    }
}
