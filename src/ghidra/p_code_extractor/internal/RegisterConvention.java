package internal;

import java.util.ArrayList;

import com.google.gson.annotations.SerializedName;

public class RegisterConvention {

    @SerializedName("calling_convention")
    private String cconv;
    @SerializedName("integer_parameter_register")
    private ArrayList<String> integerParameter;
    @SerializedName("float_parameter_register")
    private ArrayList<String> floatParameter;
    @SerializedName("return_register")
    private ArrayList<String> return_;
    @SerializedName("float_return_register")
    private ArrayList<String> floatReturn;
    @SerializedName("unaffected_register")
    private ArrayList<String> unaffected;
    @SerializedName("killed_by_call_register")
    private ArrayList<String> killedByCall;

    public RegisterConvention() {
        this.setIntegerParameter(new ArrayList<String>());
        this.setFloatParameter(new ArrayList<String>());
        this.setReturn(new ArrayList<String>());
        this.setUnaffected(new ArrayList<String>());
        this.setKilledByCall(new ArrayList<String>());
    }

    public RegisterConvention(
        String cconv, 
        ArrayList<String> integerParameter, 
        ArrayList<String> floatParameter, 
        ArrayList<String> return_,
        ArrayList<String> floatReturn,
        ArrayList<String> unaffected, 
        ArrayList<String> killedByCall
    ) {
        this.setCconv(cconv);
        this.setIntegerParameter(integerParameter);
        this.setFloatParameter(floatParameter);
        this.setReturn(return_);
        this.setFloatReturn(floatReturn);
        this.setUnaffected(unaffected);
        this.setKilledByCall(killedByCall);
    }

    public String getCconv() {
        return cconv;
    }

    public void setCconv(String cconv) {
        this.cconv = cconv;
    }

    public ArrayList<String> getIntegerParameter() {
        return integerParameter;
    }

    public void setIntegerParameter(ArrayList<String> integerParameter) {
        this.integerParameter = integerParameter;
    }

    public ArrayList<String> getFloatParameter() {
        return floatParameter;
    }

    public void setFloatParameter(ArrayList<String> floatParameter) {
        this.floatParameter = floatParameter;
    }

    public ArrayList<String> getReturn() {
        return return_;
    }

    public void setReturn(ArrayList<String> return_) {
        this.return_ = return_;
    }

    public ArrayList<String> getFloatReturn() {
        return floatReturn;
    }

    public void setFloatReturn(ArrayList<String> floatReturn) {
        this.floatReturn = floatReturn;
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
