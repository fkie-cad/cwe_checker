package symbol;

import java.util.ArrayList;

import com.google.gson.annotations.SerializedName;

import term.Arg;
import term.Tid;

public class ExternSymbol {

    @SerializedName("tid")
    private Tid tid;
    @SerializedName("addresses")
    private ArrayList<String> addresses;
    @SerializedName("name")
    private String name;
    @SerializedName("calling_convention")
    private String callingConvention;
    @SerializedName("arguments")
    private ArrayList<Arg> arguments;
    @SerializedName("no_return")
    private Boolean noReturn;

    public ExternSymbol() {
        this.setAddresses(new ArrayList<String>());
    }

    public ExternSymbol(Tid tid, ArrayList<String> addresses, String name, String callingConvention, ArrayList<Arg> arguments, Boolean noReturn) {
        this.setTid(tid);
        this.setAddresses(addresses);
        this.setName(name);
        this.setCallingConvention(callingConvention);
        this.setArguments(arguments);
        this.setNoReturn(noReturn);
    }

    public Tid getTid() {
        return tid;
    }

    public void setTid(Tid tid) {
        this.tid = tid;
    }

    public ArrayList<String> getAddresses() {
        return addresses;
    }

    public void setAddresses(ArrayList<String> addresses) {
        this.addresses = addresses;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCallingConvention() {
        return callingConvention;
    }

    public void setCallingConvention(String callingConvention) {
        this.callingConvention = callingConvention;
    }

    public ArrayList<Arg> getArguments() {
        return arguments;
    }

    public void setArguments(ArrayList<Arg> arguments) {
        this.arguments = arguments;
    }

    public Boolean getNoReturn() {
        return noReturn;
    }

    public void setNoReturn(Boolean noReturn) {
        this.noReturn = noReturn;
    }
}
