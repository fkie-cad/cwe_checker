import ghidra.program.util.VarnodeContext;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;

/**
 * Wrapper class for a simplified calling convention.
 * 
 * This model is designed for the cwe_checker's calling convention equivalent.
 * This class is used for clean and simple serialization.
 */
public class CallingConventionSimple {
    private String name;
    private ArrayList<VarnodeSimple> integer_parameter_register = new ArrayList<VarnodeSimple>();
    private ArrayList<VarnodeSimple> float_parameter_register = new ArrayList<VarnodeSimple>();
    private VarnodeSimple integer_return_register = null;
    private VarnodeSimple float_return_register = null;
    private ArrayList<VarnodeSimple> unaffected_register = new ArrayList<VarnodeSimple>();
    private ArrayList<VarnodeSimple> killed_by_call_register = new ArrayList<VarnodeSimple>();

    public CallingConventionSimple(String name, Varnode[] unaffected_register, Varnode[] killed_by_call_register,
            VarnodeContext context) {
        this.name = name;
        for (Varnode varnode : unaffected_register) {
            this.unaffected_register.add(new VarnodeSimple(varnode, context));
        }
        for (Varnode varnode : killed_by_call_register) {
            this.killed_by_call_register.add(new VarnodeSimple(varnode, context));
        }
    }

    public void setIntegerParameterRegister(ArrayList<VarnodeSimple> integer_parameter_register) {
        this.integer_parameter_register = integer_parameter_register;
    }

    public void setFloatParameterRegister(ArrayList<VarnodeSimple> float_parameter_register) {
        this.float_parameter_register = float_parameter_register;
    }

    public void setIntegerReturnRegister(VarnodeSimple returnRegister) {
        this.integer_return_register = returnRegister;
    }

    public void setFloatReturnRegister(VarnodeSimple returnRegister) {
        this.float_return_register = returnRegister;
    }
}