import java.util.ArrayList;
import java.util.HashMap;

/**
 * Wrapper class for all collected information.
 *
 * This class is used for clean and simple serialization.
 */
public class PcodeProject {

    private ArrayList<Function> functions;
    private ArrayList<RegisterProperties> register_properties;
    private String cpu_arch;
    private HashMap<String, ExternFunction> external_functions;
    private ArrayList<String> entry_points;
    private Varnode stack_pointer_register;
    private HashMap<String, CallingConvention> calling_conventions;
    private DatatypeProperties datatype_properties;
    private String image_base;

    public PcodeProject(ArrayList<Function> functions,
            ArrayList<RegisterProperties> register_properties,
            String cpu_arch,
            HashMap<String, ExternFunction> external_functions,
            ArrayList<String> entry_points,
            Varnode stack_pointer_register,
            HashMap<String, CallingConvention> calling_conventions,
            DatatypeProperties datatype_properties,
            String image_base) {
        this.functions = functions;
        this.register_properties = register_properties;
        this.cpu_arch = cpu_arch;
        this.external_functions = external_functions;
        this.entry_points = entry_points;
        this.stack_pointer_register = stack_pointer_register;
        this.calling_conventions = calling_conventions;
        this.datatype_properties = datatype_properties;
        this.image_base = image_base;
    }

}
