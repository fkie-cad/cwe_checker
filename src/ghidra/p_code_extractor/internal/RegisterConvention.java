
package internal;

import java.util.ArrayList;

import com.google.gson.annotations.SerializedName;

public class RegisterConvention {

    @SerializedName("calling_convention")
    private String cconv;
    @SerializedName("parameter_register")
    private ArrayList<String> parameter;
    @SerializedName("return_register")
    private ArrayList<String> return_;
    @SerializedName("unaffected_register")
    private ArrayList<String> unaffected;
    @SerializedName("killed_by_call_register")
    private ArrayList<String> killedByCall;

    public RegisterConvention() {
        this.setParameter(new ArrayList<String>());
        this.setReturn(new ArrayList<String>());
        this.setUnaffected(new ArrayList<String>());
        this.setKilledByCall(new ArrayList<String>());
    }

    public RegisterConvention(String cconv, ArrayList<String> parameter, ArrayList<String> return_, ArrayList<String> unaffected, ArrayList<String> killedByCall) {
        this.setCconv(cconv);
        this.setParameter(parameter);
        this.setReturn(return_);
        this.setUnaffected(unaffected);
        this.setKilledByCall(killedByCall);
    }

    public String getCconv() {
        return cconv;
    }

    public void setCconv(String cconv) {
        this.cconv = cconv;
    }

    public ArrayList<String> getParameter() {
        return parameter;
    }

    public void setParameter(ArrayList<String> parameter) {
        this.parameter = parameter;
    }

    public ArrayList<String> getReturn() {
        return return_;
    }

    public void setReturn(ArrayList<String> return_) {
        this.return_ = return_;
    }

    public ArrayList<String> getUnaffected() {
        return unaffected;
    }

    public void setUnaffected(ArrayList<String> unaffected) {
        this.unaffected = unaffected;
    }

    public ArrayList<String> getKilledByCall() {
        return killedByCall;
    }

    public void setKilledByCall(ArrayList<String> killedByCall) {
        this.killedByCall = killedByCall;
    }
}
