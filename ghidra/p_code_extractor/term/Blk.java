package term;

import java.util.ArrayList;

import com.google.gson.annotations.SerializedName;

public class Blk {
    @SerializedName("defs")
    private ArrayList<Term<Def>> defs;
    @SerializedName("jmps")
    private ArrayList<Term<Jmp>> jmps;

    public Blk() {
        this.setDefs(new ArrayList<Term<Def>>());
        this.setJmps(new ArrayList<Term<Jmp>>());
    }

    public Blk(ArrayList<Term<Def>> defs, ArrayList<Term<Jmp>> jmps) {
        this.setDefs(defs);
        this.setJmps(jmps);
    }

    public ArrayList<Term<Def>> getDefs() {
        return defs;
    }

    public void setDefs(ArrayList<Term<Def>> defs) {
        this.defs = defs;
    }

    public ArrayList<Term<Jmp>> getJmps() {
        return jmps;
    }

    public void setJmps(ArrayList<Term<Jmp>> jmps) {
        this.jmps = jmps;
    }

    public void addDef(Term<Def> def) {
        this.defs.add(def);
    }

    public void addJmp(Term<Jmp> jmp) {
        this.jmps.add(jmp);
    }

    public void addMultipleDefs(ArrayList<Term<Def>> defs) {
        this.defs.addAll(defs);
    }


}
