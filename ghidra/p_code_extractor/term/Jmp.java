package term;

import bil.ExecutionType;
import bil.Variable;

import com.google.gson.annotations.SerializedName;

public class Jmp {

    @SerializedName("type_")
    private ExecutionType.JmpType type;
    @SerializedName("mnemonic")
    private String mnemonic;
    @SerializedName("goto")
    private Label goto_;
    @SerializedName("call")
    private Call call;
    @SerializedName("condition")
    private Variable condition;
    @SerializedName("pcode_index")
    private int pcodeIndex;

    public Jmp() {
    }

    public Jmp(ExecutionType.JmpType type, String mnemonic, Label goto_, int pcodeIndex) {
        this.setType(type);
        this.setMnemonic(mnemonic);
        this.setGoto_(goto_);
        this.setPcodeIndex(pcodeIndex);
    }

    public Jmp(ExecutionType.JmpType type, String mnemonic, Call call, int pcodeIndex) {
        this.setType(type);
        this.setMnemonic(mnemonic);
        this.setCall(call);
        this.setPcodeIndex(pcodeIndex);
    }

    public Jmp(ExecutionType.JmpType type, String mnemonic, Label goto_, Variable condition, int pcodeIndex) {
        this.setType(type);
        this.setMnemonic(mnemonic);
        this.setGoto_(goto_);
        this.setCondition(condition);
        this.setPcodeIndex(pcodeIndex);
    }

    public ExecutionType.JmpType getType() {
        return type;
    }

    public void setType(ExecutionType.JmpType type) {
        this.type = type;
    }

    public String getMnemonic() {
        return mnemonic;
    }

    public void setMnemonic(String mnemonic) {
        this.mnemonic = mnemonic;
    }

    public Variable getCondition() {
        return condition;
    }

    public void setCondition(Variable condition) {
        this.condition = condition;
    }

    public Call getCall() {
        return call;
    }

    public void setCall(Call call) {
        this.call = call;
    }

    public Label getGoto_() {
        return goto_;
    }

    public void setGoto_(Label goto_) {
        this.goto_ = goto_;
    }

    public int getPcodeIndex() {
        return pcodeIndex;
    }

    public void setPcodeIndex(int pcodeIndex) {
        this.pcodeIndex = pcodeIndex;
    }

}
