import java.util.ArrayList;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import term.Blk;
import term.Def;
import term.Term;

public final class PcodeBlockData {

    // private constructor for non-instantiable classes
    private PcodeBlockData() {
        throw new UnsupportedOperationException();
    }

    /**
     * The blocks array contains at least one block for a given Ghidra generated block.
     * when the Ghidra Block is split due to branches inside it, new blocks are added to the blocks array.
     * The blocks array only contains instructions from one Ghidra block.
     */
    public static ArrayList<Term<Blk>> blocks;
    /**
     * The PcodeOp array contains the pcode operations for one assembly instruction
     */
    public static PcodeOp[] ops;
    /**
     * The temporaryDefStorage contains definitions as long as the corresponding block is unknown.
     * The block is unknown as splits can occur.
     */
    public static ArrayList<Term<Def>> temporaryDefStorage;
    /**
     * Contains the currently analysed assembly instruction
     */
    public static Instruction instruction;
    /**
     * Contains the index of the currently analysed assembly instruction in the current Ghidra block
     */
    public static int instructionIndex;
    /**
     * Contains the number of assembly instructions in the current Ghidra block
     */
    public static long numberOfInstructionsInBlock;
}
