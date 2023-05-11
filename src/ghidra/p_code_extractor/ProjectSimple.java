import java.util.ArrayList;
import java.util.HashMap;

/**
 * Wrapper class for all collected information.
 * 
 * This class is used for clean and simple serialization.
 */
public class ProjectSimple {

    private ArrayList<FunctionSimple> functions;
    private ArrayList<RegisterProperties> registerProperties;
    private String cpuArch;
    private HashMap<String, ExternFunctionSimple> external_functions;
    private ArrayList<String> entry_points;
    private VarnodeSimple stackPointerRegister;
    private HashMap<String, CallingConventionSimple> conventions;
    private DatatypeProperties datatype_properties;
    private String imagebase;

    public ProjectSimple(ArrayList<FunctionSimple> functions,
            ArrayList<RegisterProperties> registerProperties,
            String cpuArch,
            HashMap<String, ExternFunctionSimple> external_functions,
            ArrayList<String> entry_points,
            VarnodeSimple stackPointerRegister,
            HashMap<String, CallingConventionSimple> conventions,
            DatatypeProperties datatype_properties,
            String imagebase) {
        this.functions = functions;
        this.registerProperties = registerProperties;
        this.cpuArch = cpuArch;
        this.external_functions = external_functions;
        this.entry_points = entry_points;
        this.stackPointerRegister = stackPointerRegister;
        this.conventions = conventions;
        this.datatype_properties = datatype_properties;
        this.imagebase = imagebase;
    }

}
