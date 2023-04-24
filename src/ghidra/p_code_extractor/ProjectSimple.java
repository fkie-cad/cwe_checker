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
    private VarnodeSimple stackPointerRegister;
    private HashMap<String, CallingConventionSimple> conventions;
    private DatatypeProperties datatype_properties;
    private String imagebase;

    public ProjectSimple(ArrayList<FunctionSimple> functions,
            // VarnodeSimple stackPointerRegister,
            ArrayList<RegisterProperties> registerProperties,
            String cpuArch,
            VarnodeSimple stackPointerRegister,
            HashMap<String, CallingConventionSimple> conventions,
            DatatypeProperties datatype_properties,
            String imagebase) {
        this.functions = functions;
        this.registerProperties = registerProperties;
        this.cpuArch = cpuArch;
        this.stackPointerRegister = stackPointerRegister;
        this.conventions = conventions;
        this.datatype_properties = datatype_properties;
        this.imagebase = imagebase;
    }

}
