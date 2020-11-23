package internal;

import java.util.ArrayList;
import java.util.List;

import bil.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SymbolTable;
import symbol.ExternSymbolCreator;
import term.*;

public class TermCreator {

    public static SymbolTable symTab;

    // private constructor for non-instantiable classes
    private TermCreator() {
        throw new UnsupportedOperationException();
    }


    /**
     * @return: new Program Term
     * 
     * Creates the project term with an unique TID and adds external symbols.
     */
    public static Term<Program> createProgramTerm() {
        Tid progTid = new Tid(String.format("prog_%s", HelperFunctions.ghidraProgram.getMinAddress().toString()), HelperFunctions.ghidraProgram.getMinAddress().toString());
        return new Term<Program>(progTid, new Program(new ArrayList<Term<Sub>>(), HelperFunctions.addEntryPoints(symTab)));
    }


    /**
     * @param func: Ghidra function object
     * @return: new Sub Term
     * 
     * Creates a Sub Term with an unique TID consisting of the prefix sub and its entry address.
     */
    public static Term<Sub> createSubTerm(Function func) {
        return new Term<Sub>(HelperFunctions.functionEntryPoints.get(func.getEntryPoint().toString()), new Sub(func.getName(), func.getBody()));
    }


    /**
     * @param tidAddress: tid address for block
     * @param suffix: Tid suffix
     * @return: new Blk Term
     * 
     * Creates a Blk Term with an unique TID consisting of the prefix blk and its entry address.
     */
    public static Term<Blk> createBlkTerm(String tidAddress, String suffix) {
        Tid blkTid;
        if(suffix != null) {
            blkTid = new Tid(String.format("blk_%s_%s", tidAddress, suffix), tidAddress);
        } else {
            blkTid = new Tid(String.format("blk_%s", tidAddress), tidAddress);
        }
        return new Term<Blk>(blkTid, new Blk());
    }


    /**
     * 
     * @param intraJump: Indicator if jump occured inside pcode block
     * @return: new Jmp Term
     * 
     * Creates a Jmp Term with an unique TID consisting of the prefix jmp, its instruction address and the index of the pcode in the block.
     * Depending on the instruction, it either has a goto label, a goto label and a condition or a call object.
     */
    public static ArrayList<Term<Jmp>> createJmpTerm(Boolean intraJump) {
        String instrAddr = PcodeBlockData.instruction.getAddress().toString();
        Tid jmpTid = new Tid(String.format("instr_%s_%s", instrAddr, PcodeBlockData.pcodeIndex), instrAddr);
        ArrayList<Term<Jmp>> jumps = new ArrayList<Term<Jmp>>();
        int opcode = PcodeBlockData.pcodeOp.getOpcode();
        String mnemonic = PcodeBlockData.pcodeOp.getMnemonic();

        switch(opcode) {
            case PcodeOp.CALL:
            case PcodeOp.CALLIND:
            case PcodeOp.CALLOTHER:
                Call call = createCall();
                jumps.add(new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.CALL, HelperFunctions.resolveCallMenmonic(call, mnemonic), call, PcodeBlockData.pcodeIndex)));
                break;
            case PcodeOp.UNIMPLEMENTED:
                jumps.add(new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.CALL, "CALLOTHER", createCall(), PcodeBlockData.pcodeIndex)));
                break;
            case PcodeOp.CBRANCH:
                return handleConditionalBranches(jmpTid, intraJump);
            case PcodeOp.BRANCH:
            case PcodeOp.BRANCHIND:
                jumps.add(new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, mnemonic, createLabel(null), PcodeBlockData.pcodeIndex)));
                break;
            case PcodeOp.RETURN:
                jumps.add(new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.RETURN, mnemonic, createLabel(null), PcodeBlockData.pcodeIndex)));
                break;
        }

        return jumps;
    }


    /**
     * 
     * @param conditionalTid: jump site TID for CBRANCH
     * @param intraJump: indicator if jump is an intra instruction jump
     * @return: a pair of CBRANCH BRANCH jmp terms
     * 
     * Creates jmp terms for for a cbranch and an artificial fallthrough branch.
     * It checks whether the CBRANCH occured inside a pcode block. If so, the target TID for
     * the fall through BRANCH is set to the artificially generated block at the same address with
     * the start pcode index of the next block.
     */
    private static ArrayList<Term<Jmp>> handleConditionalBranches(Tid conditionalTid, Boolean intraJump) {
        ArrayList<Term<Jmp>> branches = new ArrayList<Term<Jmp>>();
        String branchSiteAddress = new String(conditionalTid.getAddress());
        Tid branchTid = new Tid(String.format("instr_%s_%s", branchSiteAddress, PcodeBlockData.pcodeIndex + 1), branchSiteAddress);
        Tid targetTid = new Tid();

        if(intraJump) {
            targetTid = new Tid(String.format("blk_%s_%s", branchSiteAddress, PcodeBlockData.pcodeIndex + 2), branchSiteAddress);
        } else {
            targetTid = new Tid(String.format("blk_%s", PcodeBlockData.instruction.getFallThrough().toString()), PcodeBlockData.instruction.getFallThrough().toString());
        }

        branches.add(new Term<Jmp>(conditionalTid, new Jmp(ExecutionType.JmpType.GOTO, PcodeBlockData.pcodeOp.getMnemonic(), TermCreator.createLabel(null), TermCreator.createVariable(PcodeBlockData.pcodeOp.getInput(1)), PcodeBlockData.pcodeIndex)));
        branches.add(new Term<Jmp>(branchTid, new Jmp(ExecutionType.JmpType.GOTO, "BRANCH", new Label(targetTid), PcodeBlockData.pcodeIndex + 1)));

        return branches;
    }


    /**
     * @return: new Def Term
     * 
     * Creates a Def Term with an unique TID consisting of the prefix def, its instruction address and the index of the pcode in the block.
     */
    public static Term<Def> createDefTerm() {
        Address instrAddr = PcodeBlockData.instruction.getAddress();
        Tid defTid = new Tid(String.format("instr_%s_%s", instrAddr.toString(), PcodeBlockData.pcodeIndex), instrAddr.toString());
        if (PcodeBlockData.pcodeOp.getMnemonic().equals("STORE")) {
            return new Term<Def>(defTid, new Def(createExpression(), PcodeBlockData.pcodeIndex));
            // cast copy instructions that have address outputs into store instructions
        }
        return new Term<Def>(defTid, new Def(createVariable(PcodeBlockData.pcodeOp.getOutput()), createExpression(), PcodeBlockData.pcodeIndex));
    }


    /**
     * @param node: Varnode source for Variable
     * @return: new Variable
     * 
     * Set register name based on being a register, virtual register, constant or ram address.
     * In case it is a virtual register, prefix the name with $U.
     * In case it is a constant, remove the const prefix from the constant.
     */
    public static Variable createVariable(Varnode node) {
        Variable var = new Variable();
        if (node.isRegister()) {
            var.setName(HelperFunctions.context.getRegister(node).getName());
            var.setIsVirtual(false);
        } else if (node.isUnique()) {
            var.setName(HelperFunctions.renameVirtualRegister(node.getAddress().toString()));
            var.setIsVirtual(true);
        } else if (node.isConstant()) {
            var.setValue(HelperFunctions.removeConstantPrefix(node.getAddress().toString()));
            var.setIsVirtual(false);
        } else if (node.isAddress()) {
            var.setAddress(node.getAddress().toString());
            var.setIsVirtual(false);
        } else if (node.isFree()) {
            var.setAddress(HelperFunctions.removeStackPrefix(node.getAddress().toString()));
            var.setIsVirtual(false);
        }

        var.setSize(node.getSize());

        return var;
    }


    /**
     * @return: new Epxression
     * 
     * Create an Expression using the input varnodes of the pcode instruction.
     */
    public static Expression createExpression() {
        String mnemonic = PcodeBlockData.pcodeOp.getMnemonic();
        List<Variable> in = new ArrayList<Variable>();

        for (Varnode input : PcodeBlockData.pcodeOp.getInputs()) {
            in.add(createVariable(input));
        }

        int inputLen = in.size();

        if (inputLen == 1) {
            return new Expression(mnemonic, in.get(0));
        }
        if (inputLen == 2) {
            return new Expression(mnemonic, in.get(0), in.get(1));
        }
        return new Expression(mnemonic, in.get(0), in.get(1), in.get(2));
    }


    /**
     * @param fallThrough: fallThrough address of branch/call
     * @return: new Label
     * 
     * Create a Label based on the branch instruction. For indirect branches and calls, it consists of a Variable, for calls of a sub TID
     * and for branches of a blk TID.
     */
    public static Label createLabel(Address fallThrough) {
        Label jumpLabel;
        if (fallThrough == null) {
            switch(PcodeBlockData.pcodeOp.getOpcode()) {
                case PcodeOp.CALL:
                case PcodeOp.CALLIND: 
                    jumpLabel = handleLabelsForCalls(PcodeBlockData.pcodeOp);
                    break;
                case PcodeOp.BRANCHIND:
                case PcodeOp.RETURN:
                    jumpLabel = new Label((Variable) createVariable(PcodeBlockData.pcodeOp.getInput(0)));
                    break;
                case PcodeOp.CALLOTHER:
                case PcodeOp.UNIMPLEMENTED:
                    jumpLabel = null;
                    break;
                default:
                    jumpLabel = new Label((Tid) new Tid(String.format("blk_%s", PcodeBlockData.pcodeOp.getInput(0).getAddress().toString()), PcodeBlockData.pcodeOp.getInput(0).getAddress().toString()));
                    break;
            }
            return jumpLabel;
        }

        return new Label((Tid) new Tid(String.format("blk_%s", fallThrough.toString()), fallThrough.toString()));
    }


    /**
     * 
     * @param pcodeOp: pcode instruction
     * @return: label depending on if indirect jump could be resolved
     * 
     * Either returns an address to the memory if not resolved or an address to a symbol
     */
    private static Label handleLabelsForCalls(PcodeOp pcodeOp) {
        Tid subTid = getTargetTid(pcodeOp);
        if (subTid != null) {
            return new Label(subTid);
        }
        if(pcodeOp.getOpcode() == PcodeOp.CALL) {
            return new Label(new Tid(String.format("sub_%s", pcodeOp.getInput(0).getAddress().toString()), pcodeOp.getInput(0).getAddress().toString()));
        }
        return new Label((Variable) createVariable(pcodeOp.getInput(0)));
    }


    /**
     * 
     * @param target: target address of indirect jump
     * @return: target id of symbol
     * 
     * Resolves the target id for an indirect jump
     */
    private static Tid getTargetTid(PcodeOp pcodeOp) {
        // First check whether the parsed address from the pcodeOp operation
        // is in the entry points map and if so, return the corresponding Tid.
        // This is a cheap operation
        String targetAddress = HelperFunctions.parseCallTargetAddress(pcodeOp);
        if(HelperFunctions.functionEntryPoints.containsKey(targetAddress)) {
            return HelperFunctions.functionEntryPoints.get(targetAddress);
        }
        // If no such target exists in the entry points map, follow the flows
        // from the instruction
        Address[] flowDestinations = PcodeBlockData.instruction.getFlows();
        // Check whether there is only one flow, so the result is unambiguous
        if(flowDestinations.length == 1) {
            Address flow = flowDestinations[0];
            // Check if the flow target is in the entry points map
            // This has to be done in case the parsed target address points 
            // to a location in a jump table
            if(HelperFunctions.functionEntryPoints.containsKey(flow.toString())) {
                return HelperFunctions.functionEntryPoints.get(flow.toString());
            }
            // In some cases indirect calls do not follow addresses directly but contents of registers
            if(targetAddress == null) {
                return null;
            }
            // If the flow points to an external address, the earlier parsed address
            // from the pcodeOp is most likely a function pointer which will be added
            // to the entry points map for later calls.
            // Also, since the function pointer address is not already in the entry points map
            // the sub TID of the corresponding external symbol will be swapped with the function
            // pointer address.
            if(flow.isExternalAddress()) {
                return ExternSymbolCreator.updateExternalSymbolLocations(flow, targetAddress, HelperFunctions.funcMan);
            }
        }

        return null;
    }


    /**
     * 
     * @return: new Call
     * 
     * Creates a Call object, using a target and return Label.
     */
    private static Call createCall() {
        String callString = null;
        Call call;
        if(PcodeBlockData.pcodeOp.getOpcode() == PcodeOp.CALLOTHER) {
            callString = HelperFunctions.ghidraProgram.getLanguage().getUserDefinedOpName((int) PcodeBlockData.pcodeOp.getInput(0).getOffset());
            call = new Call(null, createLabel(PcodeBlockData.instruction.getFallThrough()), callString);
        }
        else if(PcodeBlockData.pcodeOp.getOpcode() == PcodeOp.UNIMPLEMENTED) {
            callString = "unimplemented";
            call = new Call(null, createLabel(PcodeBlockData.instruction.getFallThrough()), callString);
        } else {
            call = new Call(createLabel(null), createLabel(PcodeBlockData.instruction.getFallThrough()));
        }

        return call;    
    }
}
