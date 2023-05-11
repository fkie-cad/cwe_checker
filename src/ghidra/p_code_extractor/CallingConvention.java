import ghidra.program.util.VarnodeContext;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;

/**
 * Wrapper class for a simplified calling convention.
 *
 * This model is designed for the cwe_checker's calling convention equivalent.
 * This class is used for clean and simple serialization.
 */
public class CallingConvention {
    private String name;
    private ArrayList<Varnode> integer_parameter_register = new ArrayList<Varnode>();
    private ArrayList<Varnode> float_parameter_register = new ArrayList<Varnode>();
    private Varnode integer_return_register = null;
    private Varnode float_return_register = null;
    private ArrayList<Varnode> unaffected_register = new ArrayList<Varnode>();
    private ArrayList<Varnode> killed_by_call_register = new ArrayList<Varnode>();

    public CallingConvention(String name, Varnode[] unaffected_register, Varnode[] killed_by_call_register,
            VarnodeContext context) {
        this.name = name;
        for (Varnode varnode : unaffected_register) {
            this.unaffected_register.add(new Varnode(varnode, context));
        }
        for (Varnode varnode : killed_by_call_register) {
            this.killed_by_call_register.add(new Varnode(varnode, context));
        }
    }

    public void setIntegerParameterRegister(ArrayList<Varnode> integer_parameter_register) {
        this.integer_parameter_register = integer_parameter_register;
    }

    public void setFloatParameterRegister(ArrayList<Varnode> float_parameter_register) {
        this.float_parameter_register = float_parameter_register;
    }

    public void setIntegerReturnRegister(Varnode returnRegister) {
        this.integer_return_register = returnRegister;
    }

    public void setFloatReturnRegister(Varnode returnRegister) {
        this.float_return_register = returnRegister;
    }
}
