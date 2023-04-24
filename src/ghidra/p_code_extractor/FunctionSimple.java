import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import ghidra.program.util.VarnodeContext;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Listing;
import java.util.ArrayList;
import ghidra.util.exception.CancelledException;

/**
 * Wrapper class for Function
 * (https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html).
 * 
 * This model is designed for the cwe_checker's Sub equivalent.
 * This class is used for clean and simple serialization.
 */
public class FunctionSimple {
    public String name;
    public String address;
    public ArrayList<BlockSimple> blocks = new ArrayList();

    public FunctionSimple(Function function, VarnodeContext context, SimpleBlockModel blockModel, TaskMonitor monitor,
            Listing listing) {
        this.address = "0x" + function.getEntryPoint().toString(false, true);
        this.name = function.getName();
        try {
            for (CodeBlock block : blockModel.getCodeBlocksContaining​(function.getBody(), monitor)) {
                blocks.add(new BlockSimple(block, context, listing));
            }
        } catch (CancelledException e) {
            System.out.println(e);
        }
    }
}