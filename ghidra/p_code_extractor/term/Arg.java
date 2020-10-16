package term;

import bil.Expression;
import bil.Variable;

import com.google.gson.annotations.SerializedName;

public class Arg {
    @SerializedName("var")
    private Variable var;
    @SerializedName("location")
    private Expression location;
    @SerializedName("intent")
    private String intent;

    public Arg() {
    }

    public Arg(Variable var, String intent) {
        this.setVar(var);
        this.setIntent(intent);
    }

    public Arg(Expression location, String intent) {
        this.setLocation(location);
        this.setIntent(intent);
    }

    public Variable getVar() {
        return var;
    }

    public void setVar(Variable var) {
        this.var = var;
    }

    public Expression getLocation() {
        return location;
    }

    public void setLocation(Expression location) {
        this.location = location;
    }

    public String getIntent() {
        return intent;
    }

    public void setIntent(String intent) {
        this.intent = intent;
    }
}
