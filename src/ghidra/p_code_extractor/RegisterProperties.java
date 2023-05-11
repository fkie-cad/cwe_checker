import ghidra.program.model.lang.Register;
import ghidra.program.util.VarnodeContext;

public class RegisterProperties {

    private String registerName;
    private String baseRegister;
    private int lsb;
    private int size;

    public RegisterProperties(Register register, VarnodeContext context) {

        this.registerName = register.getName();
        this.baseRegister = register.getBaseRegister().getName();
        this.lsb = (int) (register.getLeastSignificantBitInBaseRegister() / 8);
        this.size = context.getRegisterVarnode(register).getSize();
    }
}