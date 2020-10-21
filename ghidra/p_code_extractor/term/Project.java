package term;

import bil.Variable;
import internal.RegisterConvention;

import java.util.ArrayList;

import com.google.gson.annotations.SerializedName;

public class Project {
    @SerializedName("program")
    private Term<Program> program;
    @SerializedName("stack_pointer_register")
    private Variable stackPointerRegister;
    @SerializedName("cpu_architecture")
    private String cpuArch;
    @SerializedName("register_calling_convention")
    private ArrayList<RegisterConvention> conventions;

    public Project() {
    }

    public Project(Term<Program> program, String cpuArch, Variable stackPointerRegister, ArrayList<RegisterConvention> conventions) {
        this.setProgram(program);
        this.setCpuArch(cpuArch);
        this.setStackPointerRegister(stackPointerRegister);
        this.setRegisterConvention(conventions);
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
}
