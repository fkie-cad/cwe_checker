package term;

import com.google.gson.annotations.SerializedName;

public class Call {
    @SerializedName("target")
    private Label target;
    @SerializedName("return")
    private Label return_;
    @SerializedName("call_string")
    private String callString;

    public Call() {
    }

    public Call(Label target) {
        this.setTarget(target);
    }

    public Call(Label target, Label return_) {
        this.setTarget(target);
        this.setReturn_(return_);
    }

    public Call(Label target, Label return_, String callString) {
        this.setTarget(target);
        this.setReturn_(return_);
        this.setCallString(callString);
    }

    public Label getTarget() {
        return target;
    }

    public void setTarget(Label target) {
        this.target = target;
    }

    public Label getReturn_() {
        return return_;
    }

    public void setReturn_(Label return_) {
        this.return_ = return_;
    }

    public String getCallString() {
        return callString;
    }

    public void setCallString(String callString) {
        this.callString = callString;
    }
}
