import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.util.VarnodeContext;
import ghidra.program.model.pcode.Varnode;

/**
 * Wrapper class for a single pcode operation
 * (https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeOp.html).
 * 
 * This model contains all inputs and the output of a single pcode instruction.
 * This class is used for clean and simple serialization.
 */
public class PcodeOpSimple {
    private int pcode_index;
    private String pcodeMnemonic;
    private VarnodeSimple input0;
    private VarnodeSimple input1;
    private VarnodeSimple output;

    public PcodeOpSimple(int pcode_index, PcodeOp op, VarnodeContext context) {
        this.pcode_index = pcode_index;
        this.pcodeMnemonic = op.getMnemonic();
        if (op.getInput(0) != null) {
            this.input0 = new VarnodeSimple(op.getInput(0), context);
        }
        if (op.getInput(1) != null) {
            this.input1 = new VarnodeSimple(op.getInput(1), context);
        }
        if (op.getOutput() != null) {
            this.output = new VarnodeSimple(op.getOutput(), context);
        }

    }

}