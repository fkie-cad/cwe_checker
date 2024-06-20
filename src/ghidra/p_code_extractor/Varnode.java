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
public class Varnode {
    private String address_space;
    private String id;
    private int size;

    public Varnode(Varnode varnode, VarnodeContext context) {
        this.size = varnode.getSize();
        this.address_space = varnode.getAddress().getAddressSpace().getName();
        this.id = varnode.getAddress().toString("0x");
        if (context.getRegister(varnode) != null) {
            this.id = context.getRegister(varnode).getName();
        }
    }

    public Varnode(Register register) {
        this.id = register.getName();
        this.size = (int) register.getBitLength() / 8;
        this.address_space = register.getAddressSpace().getName();
    }

    public String toString() {
        return String.format("(%s, %s, %d)", this.address_space, this.id, this.size);
    }

    public String getId() {
        return this.id;
    }

}