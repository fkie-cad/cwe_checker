import ghidra.program.model.listing.Instruction;
import ghidra.program.util.VarnodeContext;
import ghidra.program.model.pcode.PcodeOp;
import java.util.ArrayList;

/**
 * Wrapper class for a single ISA instruction
 * (https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html).
 * 
 * This model contains the list of pcode instructions representing a single ISA
 * instruction.
 * This class is used for clean and simple serialization.
 */
public class InstructionSimple {
    public String mnemonic;
    public String address;
    public ArrayList<PcodeOpSimple> pcodeOps = new ArrayList();

    public InstructionSimple(Instruction instruction, VarnodeContext context) {
        this.mnemonic = instruction.toString();
        this.address = "0x" + instruction.getAddressString(false, true);
        PcodeOp[] pcodes = instruction.getPcode(true);
        for (int i = 0; i < pcodes.length; i++) {
            pcodeOps.add(new PcodeOpSimple(i, pcodes[i], context));

        }

    }
}