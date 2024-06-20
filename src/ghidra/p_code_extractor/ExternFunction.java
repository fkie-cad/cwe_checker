import java.util.ArrayList;
import java.util.HashMap;
import ghidra.program.model.address.Address;

/**
 * Wrapper class for external Function
 * 
 * 
 * Thunk functions' addresses are referenced as addresses
 * This class is used for clean and simple serialization.
 */
public class ExternFunction {
    private String name;
    private String calling_convention;
    private ArrayList<Varnode> parameters = new ArrayList<Varnode>();
    private Varnode return_location;
    private ArrayList<String> thunks;
    private Boolean has_no_return;
    private Boolean has_var_args;

    public ExternFunction(String name, String cconv, ArrayList<Varnode> parameters,
            Varnode return_location, Boolean has_no_return, Boolean has_var_args) {
        this.name = name;
        this.calling_convention = cconv;
        this.parameters = parameters;
        this.return_location = return_location;
        this.has_no_return = has_no_return;
        this.has_var_args = has_var_args;
        this.thunks = new ArrayList<String>();
    }

    public void add_thunk_function_address(Address address) {
        this.thunks.add("0x" + address.toString(false, false));
    }
}