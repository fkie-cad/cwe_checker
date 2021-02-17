package bil;

import com.google.gson.annotations.SerializedName;

public class Expression {

    @SerializedName("mnemonic")
    private String mnemonic;
    @SerializedName("input0")
    private Variable input0;
    @SerializedName("input1")
    private Variable input1;
    @SerializedName("input2")
    private Variable input2;

    public Expression() {
    }

    public Expression(String mnemonic, Variable input0) {
        this.setMnemonic(mnemonic);
        this.setInput0(input0);
    }

    public Expression(String mnemonic, Variable input0, Variable input1) {
        this.setMnemonic(mnemonic);
        this.setInput0(input0);
        this.setInput1(input1);
    }

    public Expression(String mnemonic, Variable input0, Variable input1, Variable input2) {
        this.setMnemonic(mnemonic);
        this.setInput0(input0);
        this.setInput1(input1);
        this.setInput2(input2);
    }

    public String getMnemonic() {
        return mnemonic;
    }

    public void setMnemonic(String mnemonic) {
        this.mnemonic = mnemonic;
    }

    public Variable getInput0() {
        return input0;
    }

    public void setInput0(Variable input0) {
        this.input0 = input0;
    }

    public Variable getInput1() {
        return input1;
    }

    public void setInput1(Variable input1) {
        this.input1 = input1;
    }

    public Variable getInput2() {
        return input2;
    }

    public void setInput2(Variable input2) {
        this.input2 = input2;
    }

}
