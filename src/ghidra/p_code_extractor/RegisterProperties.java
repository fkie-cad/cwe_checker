import ghidra.program.model.lang.Register;
import ghidra.program.util.VarnodeContext;

public class RegisterProperties {

    private String register_name;
    private String base_register;
    private int lsb;
    private int size;

    public RegisterProperties(Register register, VarnodeContext context) {

        this.register_name = register.getName();
        this.base_register = register.getBaseRegister().getName();
        this.lsb = (int) (register.getLeastSignificantBitInBaseRegister() / 8);
        this.size = context.getRegisterVarnode(register).getSize();
    }
}