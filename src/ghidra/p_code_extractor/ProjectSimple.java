import java.util.ArrayList;
import java.util.HashMap;

/**
 * Wrapper class for all collected information.
 * 
 * This class is used for clean and simple serialization.
 */
public class ProjectSimple {

    private ArrayList<FunctionSimple> functions;
    private ArrayList<RegisterProperties> register_properties;
    private String cpu_arch;
    private HashMap<String, ExternFunctionSimple> external_functions;
    private ArrayList<String> entry_points;
    private VarnodeSimple stack_pointer_register;
    private HashMap<String, CallingConventionSimple> conventions;
    private DatatypeProperties datatype_properties;
    private String imagebase;

    public ProjectSimple(ArrayList<FunctionSimple> functions,
            ArrayList<RegisterProperties> register_properties,
            String cpu_arch,
            HashMap<String, ExternFunctionSimple> external_functions,
            ArrayList<String> entry_points,
            VarnodeSimple stack_pointer_register,
            HashMap<String, CallingConventionSimple> conventions,
            DatatypeProperties datatype_properties,
            String imagebase) {
        this.functions = functions;
        this.register_properties = register_properties;
        this.cpu_arch = cpu_arch;
        this.external_functions = external_functions;
        this.entry_points = entry_points;
        this.stack_pointer_register = stack_pointer_register;
        this.conventions = conventions;
        this.datatype_properties = datatype_properties;
        this.imagebase = imagebase;
    }

}
