package term;

import bil.Variable;
import com.google.gson.annotations.SerializedName;

public class Label {

    @SerializedName("Direct")
    private Tid direct;
    @SerializedName("Indirect")
    private Variable indirect;

    public Label(Tid tid) {
        this.setDirect(tid);
        this.setIndirect(null);
    }

    public Label(Variable variable) {
        this.setDirect(null);
        this.setIndirect(variable);
    }

    public Tid getDirect() {
        return direct;
    }

    public void setDirect(Tid direct) {
        this.direct = direct;
    }

    public Variable getIndirect() {
        return indirect;
    }

    public void setIndirect(Variable indirect) {
        this.indirect = indirect;
    }

}
