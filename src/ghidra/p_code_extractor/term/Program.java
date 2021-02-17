package term;

import java.util.ArrayList;

import com.google.gson.annotations.SerializedName;

import symbol.ExternSymbol;

public class Program {

    @SerializedName("subs")
    private ArrayList<Term<Sub>> subs;
    @SerializedName("extern_symbols")
    private ArrayList<ExternSymbol> externSymbols;
    @SerializedName("entry_points")
    private ArrayList<Tid> entryPoints;
    @SerializedName("image_base")
    private String imageBase;

    public Program() {
    }

    public Program(ArrayList<Term<Sub>> subs) {
        this.setSubs(subs);
    }

    public Program(ArrayList<Term<Sub>> subs, ArrayList<Tid> entryPoints, String imageBase) {
        this.setSubs(subs);
        this.setEntryPoints(entryPoints);
        this.setImageBase(imageBase);
    }


    public ArrayList<Term<Sub>> getSubs() {
        return subs;
    }

    public void setSubs(ArrayList<Term<Sub>> subs) {
        this.subs = subs;
    }

    public void addSub(Term<Sub> sub) {
        this.subs.add(sub);
    }

    public ArrayList<ExternSymbol> getExternSymbols() {
        return externSymbols;
    }

    public void setExternSymbols(ArrayList<ExternSymbol> extern_symbols) {
        this.externSymbols = extern_symbols;
    }

    public ArrayList<Tid> getEntryPoints() {
        return entryPoints;
    }

    public void setEntryPoints(ArrayList<Tid> entryPoints) {
        this.entryPoints = entryPoints;
    }

    public String getImageBase() {
        return imageBase;
    }

    public void setImageBase(String imageBase) {
        this.imageBase = imageBase;
    }
}
