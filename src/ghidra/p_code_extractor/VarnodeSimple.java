import ghidra.program.util.VarnodeContext;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.lang.Register;

/**
 * Wrapper class for Varnode
 * (https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/Varnode.html).
 * 
 * Varnodes represent registers, stack offset and other values and are used as
 * operants for
 * pcode instructions.
 * This class is used for clean and simple serialization.
 */
public class VarnodeSimple {
    private String addressspace;
    private String id;
    private int size;

    public VarnodeSimple(Varnode varnode, VarnodeContext context) {
        this.size = varnode.getSize();
        this.addressspace = varnode.getAddress().getAddressSpace().getName();
        this.id = varnode.getAddress().toString("0x");
        if (context.getRegister(varnode) != null) {
            this.id = context.getRegister(varnode).getName();
        }
    }

    public VarnodeSimple(Register register) {
        this.id = register.getName();
        this.size = (int) register.getBitLength() / 8;
        this.addressspace = register.getAddressSpace().getName();
    }

    public String toString() {
        return String.format("(%s, %s, %d)", this.addressspace, this.id, this.size);
    }

    public String getId() {
        return this.id;
    }

}