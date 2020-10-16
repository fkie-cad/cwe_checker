package term;

import bil.Expression;
import bil.Variable;

import com.google.gson.annotations.SerializedName;

public class Def {

    @SerializedName("lhs")
    private Variable lhs;
    @SerializedName("rhs")
    private Expression rhs;
    @SerializedName("pcode_index")
    private int pcodeIndex;

    public Def() {
    }

    public Def(Expression rhs, int pcodeIndex) {
        this.setRhs(rhs);
        this.setPcodeIndex(pcodeIndex);
    }

    public Def(Variable lhs, Expression rhs, int pcodeIndex) {
        this.setLhs(lhs);
        this.setRhs(rhs);
        this.setPcodeIndex(pcodeIndex);
    }

    public Variable getLhs() {
        return lhs;
    }

    public void setLhs(Variable lhs) {
        this.lhs = lhs;
    }

    public Expression getRhs() {
        return rhs;
    }

    public void setRhs(Expression rhs) {
        this.rhs = rhs;
    }

    public int getPcodeIndex() {
        return pcodeIndex;
    }

    public void setPcodeIndex(int pcodeIndex) {
        this.pcodeIndex = pcodeIndex;
    }
}
