package bil;

import com.google.gson.annotations.SerializedName;

public class RegisterProperties {

    @SerializedName("register")
    private String register;
    @SerializedName("base_register")
    private String baseRegister;
    @SerializedName("lsb")
    private int lsb;
    @SerializedName("size")
    private int size;


    public RegisterProperties(String register, String baseRegister, int lsb, int size) {
        this.setRegister(register);
        this.setBaseRegister(baseRegister);
        this.setLsb(lsb);
        this.setSize(size);
    }

    public String getRegister() {
        return register;
    }

    public void setRegister(String register) {
        this.register = register;
    }

    public String getBaseRegister() {
        return baseRegister;
    }

    public void setBaseRegister(String baseRegister) {
        this.baseRegister = baseRegister;
    }

    public int getLsb() {
        return lsb;
    }

    public void setLsb(int lsb) {
        this.lsb = lsb;
    }

    public int getSize() {
        return size;
    }

    public void setSize(int size) {
        this.size = size;
    }
    
}
