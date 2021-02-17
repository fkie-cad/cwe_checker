package term;

import java.util.ArrayList;

import com.google.gson.annotations.SerializedName;

import ghidra.program.model.address.AddressSetView;

public class Sub {
    @SerializedName("name")
    private String name;
    private AddressSetView addresses;
    @SerializedName("blocks")
    private ArrayList<Term<Blk>> blocks;

    public Sub() {
    }

    public Sub(String name, AddressSetView addresses) {
        this.setName(name);
        this.setAddresses(addresses);
    }

    public Sub(String name, ArrayList<Term<Blk>> blocks, AddressSetView addresses) {
        this.setName(name);
        this.setBlocks(blocks);
        this.setAddresses(addresses);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public ArrayList<Term<Blk>> getBlocks() {
        return blocks;
    }

    public void setBlocks(ArrayList<Term<Blk>> blocks) {
        this.blocks = blocks;
    }

    public void addBlock(Term<Blk> block) {
        this.blocks.add(block);
    }

    public AddressSetView getAddresses() {
        return addresses;
    }

    public void setAddresses(AddressSetView addresses) {
        this.addresses = addresses;
    }
}
