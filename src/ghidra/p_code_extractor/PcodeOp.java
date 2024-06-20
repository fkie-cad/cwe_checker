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
public class PcodeOp {
    private int pcode_index;
    private String pcode_mnemonic;
    private Varnode input0;
    private Varnode input1;
    private Varnode input2;
    private Varnode output;

    public PcodeOp(int pcode_index, PcodeOp op, VarnodeContext context) {
        this.pcode_index = pcode_index;
        this.pcode_mnemonic = op.getMnemonic();
        if (op.getInput(0) != null) {
            this.input0 = new Varnode(op.getInput(0), context);
        }
        if (op.getInput(1) != null) {
            this.input1 = new Varnode(op.getInput(1), context);
        }
        if (op.getInput(2) != null) {
            this.input2 = new Varnode(op.getInput(2), context);
        }
        if (op.getOutput() != null) {
            this.output = new Varnode(op.getOutput(), context);
        }

    }

}