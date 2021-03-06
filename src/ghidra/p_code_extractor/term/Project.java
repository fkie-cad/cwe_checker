package term;

import bil.DatatypeProperties;
import bil.RegisterProperties;
import bil.Variable;
import internal.RegisterConvention;

import java.util.ArrayList;

import com.google.gson.annotations.SerializedName;

public class Project {
    @SerializedName("program")
    private Term<Program> program;
    @SerializedName("stack_pointer_register")
    private Variable stackPointerRegister;
    @SerializedName("register_properties")
    private ArrayList<RegisterProperties> registerProperties;
    @SerializedName("cpu_architecture")
    private String cpuArch;
    @SerializedName("register_calling_convention")
    private ArrayList<RegisterConvention> conventions;
    @SerializedName("datatype_properties")
    private DatatypeProperties datatype_properties;

    public Project() {
    }

    public Project(
        Term<Program> program, 
        String cpuArch,
        Variable stackPointerRegister, 
        ArrayList<RegisterConvention> conventions, 
        DatatypeProperties datatype_properties
    ) {
        this.setProgram(program);
        this.setCpuArch(cpuArch);
        this.setStackPointerRegister(stackPointerRegister);
        this.setRegisterConvention(conventions);
        this.setDatatypeProperties(datatype_properties);
    }

    public Term<Program> getProgram() {
        return program;
    }

    public void setProgram(Term<Program> program) {
        this.program = program;
    }

    public Variable getStackPointerRegister() {
        return stackPointerRegister;
    }

    public void setStackPointerRegister(Variable stackPointerRegister) {
        this.stackPointerRegister = stackPointerRegister;
    }

    public String getCpuArch() {
        return cpuArch;
    }

    public void setCpuArch(String cpuArch) {
        this.cpuArch = cpuArch;
    }

    public ArrayList<RegisterConvention> getRegisterConvention() {
        return conventions;
    }

    public void setRegisterConvention(ArrayList<RegisterConvention> conventions) {
        this.conventions = conventions;
    }

    public ArrayList<RegisterProperties> getRegisterProperties() {
        return registerProperties;
    }

    public void setRegisterProperties(ArrayList<RegisterProperties> registerProperties) {
        this.registerProperties = registerProperties;
    }

    public DatatypeProperties getDatatypeProperties() {
        return datatype_properties;
    }

    public void setDatatypeProperties(DatatypeProperties datatype_properties) {
        this.datatype_properties = datatype_properties;
    }
}
