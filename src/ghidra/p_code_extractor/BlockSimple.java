import ghidra.program.model.block.CodeBlock;
import ghidra.program.util.VarnodeContext;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Instruction;
import java.util.ArrayList;

/**
 * Wrapper class for a basic block of pcode instructions.
 * 
 * This class is used for clean and simple serialization.
 */
public class BlockSimple {
    public String address;
    public ArrayList<InstructionSimple> instructions = new ArrayList();

    public BlockSimple(CodeBlock block, VarnodeContext context, Listing listing) {
        this.address = block.getFirstStartAddress().toString(false, true);
        for (Instruction instr : listing.getInstructions(block, true)) {
            instructions.add(new InstructionSimple(instr, context));
        }

    }
}