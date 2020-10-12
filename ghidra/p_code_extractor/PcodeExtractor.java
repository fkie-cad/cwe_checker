
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.StreamSupport;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.EnumUtils;

import bil.*;
import term.*;
import symbol.ExternSymbol;
import serializer.Serializer;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;

public class PcodeExtractor extends GhidraScript {

    List<String> jumps = new ArrayList<String>() {{
        add("BRANCH");
        add("CBRANCH");
        add("BRANCHIND");
        add("CALL");
        add("CALLIND");
        add("CALLOTHER");
        add("RETURN");
    }};

    Term<Program> program = null;
    FunctionManager funcMan;
    ghidra.program.model.listing.Program ghidraProgram;
    VarnodeContext context;
    String cpuArch;

    Set<String> binOps = EnumUtils.getEnumMap(ExecutionType.BinOpType.class).keySet();
    Set<String> unOps = EnumUtils.getEnumMap(ExecutionType.UnOpType.class).keySet();
    Set<String> casts = EnumUtils.getEnumMap(ExecutionType.CastType.class).keySet();


    /**
     * Entry point to Ghidra Script. Calls serializer after processing of Terms.
     */
    @Override
    protected void run() throws Exception {
        ghidraProgram = currentProgram;
        funcMan = ghidraProgram.getFunctionManager();
        SimpleBlockModel simpleBM = new SimpleBlockModel(ghidraProgram);
        Listing listing = ghidraProgram.getListing();
        context = new VarnodeContext(ghidraProgram, ghidraProgram.getProgramContext(), ghidraProgram.getProgramContext());
        cpuArch = getCpuArchitecture();

        program = createProgramTerm();
        Project project = createProject();
        program = iterateFunctions(simpleBM, listing);

        String jsonPath = getScriptArgs()[0];
        Serializer ser = new Serializer(project, jsonPath);
        ser.serializeProject();
        TimeUnit.SECONDS.sleep(3);

    }


    /**
     * @return: CPU architecture as string.
     * 
     * Uses Ghidra's language id to extract the CPU arch as "arch-bits" e.g. x86_64, x86_32 etc.
     */
    protected String getCpuArchitecture() {
        String langId = ghidraProgram.getCompilerSpec().getLanguage().getLanguageID().getIdAsString();
        String[] arch = langId.split(":");
        return arch[0] + "_" + arch[2];
    }


    /**
     * @param simpleBM: Simple Block Model to iterate over blocks
     * @param listing:  Listing to get assembly instructions
     * @return: Processed Program Term
     * 
     * Iterates over functions to create sub terms and calls the block iterator to add all block terms to each subroutine.
     */
    protected Term<Program> iterateFunctions(SimpleBlockModel simpleBM, Listing listing) {
        FunctionIterator functions = funcMan.getFunctionsNoStubs(true);
        for (Function func : functions) {
            if (!func.isThunk()) {
                Term<Sub> currentSub = createSubTerm(func);
                currentSub.getTerm().setBlocks(iterateBlocks(currentSub, simpleBM, listing));
                program.getTerm().addSub(currentSub);
            }
        }

        return program;
    }


    /**
     * @param currentSub: Current Sub Term to processed
     * @param simpleBM:   Simple Block Model to iterate over blocks
     * @param listing:    Listing to get assembly instructions
     * @return: new ArrayList of Blk Terms
     * 
     * Iterates over all blocks and calls the instruction iterator to add def and jmp terms to each block.
     */
    protected ArrayList<Term<Blk>> iterateBlocks(Term<Sub> currentSub, SimpleBlockModel simpleBM, Listing listing) {
        ArrayList<Term<Blk>> blockTerms = new ArrayList<Term<Blk>>();
        try {
            CodeBlockIterator blockIter = simpleBM.getCodeBlocksContaining(currentSub.getTerm().getAddresses(), getMonitor());
            while(blockIter.hasNext()) {
                CodeBlock currentBlock = blockIter.next();
                ArrayList<Term<Blk>> newBlockTerms = iterateInstructions(createBlkTerm(currentBlock.getFirstStartAddress().toString(), null), listing, currentBlock);
                Term<Blk> lastBlockTerm = newBlockTerms.get(newBlockTerms.size() - 1);
                handlePossibleDefinitionAtEndOfBlock(lastBlockTerm, currentBlock);
                blockTerms.addAll(newBlockTerms);
            }
        } catch (CancelledException e) {
            System.out.printf("Could not retrieve all basic blocks comprised by function: %s\n", currentSub.getTerm().getName());
        }

        return blockTerms;
    }


    /**
     * @param lastBlockTerm: latest generated block term
     * @param currentBlock: current code block from which the block term was generated
     * 
     * Checks whether the latest generated block term ends on a definition and gets the first
     * destination address of the current code block, if available, to create an artificial jump
     */
    protected void handlePossibleDefinitionAtEndOfBlock(Term<Blk> lastBlockTerm, CodeBlock currentBlock) {
        if(lastInstructionIsDef(lastBlockTerm)) {
            String destinationAddress = getGotoAddressForDestination(currentBlock);
            if(destinationAddress != null) {
                String instrAddress = lastBlockTerm.getTerm().getDefs().get(lastBlockTerm.getTerm().getDefs().size()-1).getTid().getAddress();
                addJumpToCurrentBlock(lastBlockTerm.getTerm(), instrAddress, destinationAddress, null);
            }
        }
    }


    /**
     * @param currentBlock
     * @return: goto address for jump
     * 
     * Checks whether a destination address exists
     */
    protected String getGotoAddressForDestination(CodeBlock currentBlock) {
        try {
            CodeBlockReferenceIterator destinations = currentBlock.getDestinations(getMonitor());
            if(destinations.hasNext()) {
                return destinations.next().getDestinationAddress().toString();
            }
        } catch (CancelledException e) {
            System.out.printf("Could not retrieve destinations for codeBlock at: %s\n", currentBlock.getFirstStartAddress());
        }

        return null;
    }


    /**
     * @param block:     Blk Term to be filled with instructions
     * @param listing:   Assembly instructions
     * @param codeBlock: codeBlock for retrieving instructions
     * @return: new array of Blk Terms
     * 
     * Iterates over assembly instructions and processes each of the pcode blocks.
     * Handles empty block by adding a jump Term with fallthrough address
     */
    protected ArrayList<Term<Blk>> iterateInstructions(Term<Blk> block, Listing listing, CodeBlock codeBlock) {
        int instructionIndex = 0;
        InstructionIterator instructions = listing.getInstructions(codeBlock, true);
        long numberOfInstructionsInBlock = StreamSupport.stream(listing.getInstructions(codeBlock, true).spliterator(), false).count();
        ArrayList<Term<Blk>> blocks = new ArrayList<Term<Blk>>();
        blocks.add(block);

        for (Instruction instr : instructions) {
            processPcode(blocks, instr, instructionIndex, numberOfInstructionsInBlock);
            instructionIndex++;
        }

        if (blocks.get(0).getTerm().getDefs().isEmpty() && blocks.get(0).getTerm().getJmps().isEmpty()) {
            handleEmptyBlock(blocks, codeBlock);
        }

        return blocks;
    }


    /**
     * @param codeBlock: Current empty block
     * @return New jmp term containing fall through address
     * 
     * Adds fallthrough address jump to empty block if available
     */
    protected void handleEmptyBlock(ArrayList<Term<Blk>> blocks, CodeBlock codeBlock) {
        try {
            CodeBlockReferenceIterator destinations = codeBlock.getDestinations(getMonitor());
            if(destinations.hasNext()) {
                Tid jmpTid = new Tid(String.format("instr_%s_%s", codeBlock.getFirstStartAddress().toString(), 0), codeBlock.getFirstStartAddress().toString());
                Tid gotoTid = new Tid();
                String destAddr = destinations.next().getDestinationBlock().getFirstStartAddress().toString();
                gotoTid.setId(String.format("blk_%s", destAddr));
                gotoTid.setAddress(destAddr);
                blocks.get(0).getTerm().addJmp(new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, "BRANCH", new Label((Tid) gotoTid), 0)));
            }
        } catch (CancelledException e) {
            System.out.printf("Could not retrieve destinations for block at: %s\n", codeBlock.getFirstStartAddress().toString());
        }
    }


    /**
     * @param blocks: array of block terms 
     * @param instruction: assembly instruction
     * @param instructionIndex: index of the assembly instruction
     * @param numberOfInstructionsInBlock: number of assembly instructions in Ghidra generated block
     * 
     * Checks whether the assembly instruction is a nop instruction and adds a jump to the block.
     * Checks whether a jump occured within a ghidra generated pcode block and fixes the control flow
     * by adding missing jumps between artificially generated blocks.
     */
    protected void processPcode(ArrayList<Term<Blk>> blocks, Instruction instruction, int instructionIndex, long numberOfInstructionsInBlock) {
        PcodeOp[] ops = instruction.getPcode(true);
        if(ops.length == 0) {
            addJumpToCurrentBlock(blocks.get(blocks.size()-1).getTerm(), instruction.getAddress().toString(), instruction.getFallThrough().toString(), null);
            return;
        }

        ArrayList<Term<Def>> temporaryDefStorage = new ArrayList<Term<Def>>();
        Boolean intraInstructionJumpOccured = iteratePcode(blocks, temporaryDefStorage, instruction, instructionIndex, numberOfInstructionsInBlock, ops);

        fixControlFlowWhenIntraInstructionJumpOccured(intraInstructionJumpOccured, blocks, temporaryDefStorage, instruction);

        if(!temporaryDefStorage.isEmpty()) {
            blocks.get(blocks.size() - 1).getTerm().addMultipleDefs(temporaryDefStorage);
        }
    }


    /**
     * @param blocks: array of block terms
     * @param temporaryDefStorage: temporarily stored definitions
     * @param instruction: assembly instruction
     * @param instructionIndex: index of assembly instruction
     * @param numberOfInstructionsInBlock: number of assembly instructions in Ghidra generated block
     * @param ops: pcode ops for current assembly instruction
     * @return: indicator if jump occured within pcode block
     */
    protected Boolean iteratePcode(ArrayList<Term<Blk>> blocks, ArrayList<Term<Def>> temporaryDefStorage, Instruction instruction, int instructionIndex, long numberOfInstructionsInBlock, PcodeOp[] ops) {
        int numberOfPcodeOps = ops.length;
        Boolean intraInstructionJumpOccured = false;
        for(int pcodeIndex = 0; pcodeIndex < numberOfPcodeOps; pcodeIndex++) {
            PcodeOp pcodeOp = ops[pcodeIndex];
            String mnemonic = pcodeOp.getMnemonic();
            if (this.jumps.contains(mnemonic)) {
                intraInstructionJumpOccured = processJump(blocks, instruction, pcodeOp, mnemonic, temporaryDefStorage, instructionIndex, numberOfInstructionsInBlock, numberOfPcodeOps, pcodeIndex, intraInstructionJumpOccured);
            } else {
                temporaryDefStorage.add(createDefTerm(pcodeIndex, pcodeOp, instruction.getAddress()));
            }
        }

        return intraInstructionJumpOccured;
    }


    /**
     * @param intraInstructionJumpOccured: indicator if jump occured within pcode block
     * @param blocks: array of block terms
     * @param temporaryDefStorage: temporarily stored definitions
     * @param instruction: assembly instruction
     * 
     * fixes the control flow by adding missing jumps between artificially generated blocks.
     */
    protected void fixControlFlowWhenIntraInstructionJumpOccured(Boolean intraInstructionJumpOccured, ArrayList<Term<Blk>> blocks, ArrayList<Term<Def>> temporaryDefStorage, Instruction instruction) {
        // A block is split when a Pcode Jump Instruction occurs in the PcodeBlock. 
        // A jump is added to the end of the split block to the pcode block of the next assembly instruction
        if(intraInstructionJumpOccured) {
            Term<Blk> lastBlock = blocks.get(blocks.size() - 1);
            if(!temporaryDefStorage.isEmpty()) {
                addMissingJumpAfterInstructionSplit(blocks, lastBlock, temporaryDefStorage, instruction);
            }
        }
    }


    /**
     * @param blocks: array of block terms
     * @param lastBlock: last block before split
     * @param temporaryDefStorage: temporarily stored definitions
     * @param instruction: assembly instruction
     * 
     * Adds a missing jump after a Ghidra generated block has been split to maintain the control flow
     * between the blocks
     */
    protected void addMissingJumpAfterInstructionSplit(ArrayList<Term<Blk>> blocks, Term<Blk> lastBlock, ArrayList<Term<Def>> temporaryDefStorage, Instruction instruction) {
        lastBlock.getTerm().addMultipleDefs(temporaryDefStorage);
        addJumpToCurrentBlock(lastBlock.getTerm(), instruction.getAddress().toString(), instruction.getFallThrough().toString(), null);
        blocks.add(createBlkTerm(instruction.getFallThrough().toString(), null));
        temporaryDefStorage.clear();
    }


    /**
     * 
     * @param blocks: array pf block terms
     * @param instruction: assembly instruction
     * @param pcodeOp: pcode instruction
     * @param mnemonic: pcode mnemonic
     * @param temporaryDefStorage: temporarily stored definitions
     * @param instructionIndex: index of the current assembly instruction
     * @param numberOfInstructionsInBlock: number of assembly instructions in Ghidra generated block
     * @param numberOfPcodeOps: number of pcode instruction in pcode block
     * @param pcodeIndex: index of current pcode instruction
     * @param intraInstructionJumpOccured: indicator whether a jump occured inside a pcode block
     * @return: indicator whether a jump occured inside a pcode block
     * 
     * Processes jump pcode instruction by checking where it occurs.
     * Distinguishes between jumps inside a pcode block and jumps at the end of a pcode block
     */
    protected Boolean processJump(ArrayList<Term<Blk>> blocks, Instruction instruction, PcodeOp pcodeOp, String mnemonic, ArrayList<Term<Def>> temporaryDefStorage, 
    int instructionIndex, long numberOfInstructionsInBlock, int numberOfPcodeOps, int pcodeIndex, Boolean intraInstructionJumpOccured) {

        int currentBlockCount = blocks.size();
        Term<Blk> currentBlock = blocks.get(currentBlockCount - 1);

        if(pcodeIndex < numberOfPcodeOps - 1) {
            intraInstructionJumpOccured = processJumpInPcodeBlock(blocks, instruction, pcodeOp, mnemonic, temporaryDefStorage, instructionIndex, 
            numberOfInstructionsInBlock, numberOfPcodeOps, pcodeIndex, intraInstructionJumpOccured, currentBlock);
            temporaryDefStorage.clear();
        } else {
            processJumpAtEndOfPcodeBlocks(blocks, instruction, pcodeOp, mnemonic, temporaryDefStorage, instructionIndex, 
            numberOfInstructionsInBlock, numberOfPcodeOps, pcodeIndex, intraInstructionJumpOccured, currentBlock);
        }

        return intraInstructionJumpOccured;
    }


    /**
     * 
     * @param blocks: array pf block terms
     * @param instruction: assembly instruction
     * @param pcodeOp: pcode instruction
     * @param mnemonic: pcode mnemonic
     * @param temporaryDefStorage: temporarily stored definitions
     * @param instructionIndex: index of the current assembly instruction
     * @param numberOfInstructionsInBlock: number of assembly instructions in Ghidra generated block
     * @param numberOfPcodeOps: number of pcode instruction in pcode block
     * @param pcodeIndex: index of current pcode instruction
     * @param intraInstructionJumpOccured: indicator whether a jump occured inside a pcode block
     * @param currentBlock: current block term
     * @return: indicator whether a jump occured inside a pcode block
     * 
     * Process jumps at the end of pcode blocks
     * If it is a return block, the call return address is changed to the current block
     */
    protected Boolean processJumpAtEndOfPcodeBlocks(ArrayList<Term<Blk>> blocks, Instruction instruction, PcodeOp pcodeOp, String mnemonic, ArrayList<Term<Def>> temporaryDefStorage, 
    int instructionIndex, long numberOfInstructionsInBlock, int numberOfPcodeOps, int pcodeIndex, Boolean intraInstructionJumpOccured, Term<Blk> currentBlock) {
        // Case 2: jump at the end of pcode group but not end of ghidra generated block.
        if(instructionIndex < numberOfInstructionsInBlock - 1) {
            blocks.add(createBlkTerm(instruction.getFallThrough().toString(), null));
        }
        // Case 3: jmp at last pcode op at last instruction in ghidra generated block
        // If Case 2 is true, the 'currentBlk' will be the second to last block as the new block is for the next instruction
        if(pcodeOp.getOpcode() == PcodeOp.RETURN && currentBlock.getTid().getId().endsWith("_r")) {
            redirectCallReturn(currentBlock, instruction, pcodeOp);
            return intraInstructionJumpOccured;
        }
        currentBlock.getTerm().addMultipleDefs(temporaryDefStorage);
        currentBlock.getTerm().addJmp(createJmpTerm(instruction, pcodeIndex, pcodeOp, mnemonic, instruction.getAddress()));
        temporaryDefStorage.clear();

        return intraInstructionJumpOccured;
    }


    /**
     * 
     * @param blocks: array pf block terms
     * @param instruction: assembly instruction
     * @param pcodeOp: pcode instruction
     * @param mnemonic: pcode mnemonic
     * @param temporaryDefStorage: temporarily stored definitions
     * @param instructionIndex: index of the current assembly instruction
     * @param numberOfInstructionsInBlock: number of assembly instructions in Ghidra generated block
     * @param numberOfPcodeOps: number of pcode instruction in pcode block
     * @param pcodeIndex: index of current pcode instruction
     * @param intraInstructionJumpOccured: indicator whether a jump occured inside a pcode block
     * @param currentBlock: current block term
     * @return: indicator whether a jump occured inside a pcode block
     * 
     * Processes a jump inside a pcode block and distinguishes between intra jumps and call return pairs.
     */
    protected Boolean processJumpInPcodeBlock(ArrayList<Term<Blk>> blocks, Instruction instruction, PcodeOp pcodeOp, String mnemonic, ArrayList<Term<Def>> temporaryDefStorage, 
    int instructionIndex, long numberOfInstructionsInBlock, int numberOfPcodeOps, int pcodeIndex, Boolean intraInstructionJumpOccured, Term<Blk> currentBlock) {
        if(!isCall(pcodeOp)) {
            intraInstructionJumpOccured = true;
            handleIntraInstructionJump(blocks, temporaryDefStorage, currentBlock.getTerm(), instruction, pcodeOp, pcodeIndex, instructionIndex);
        } else {
            handleCallReturnPair(blocks, temporaryDefStorage, currentBlock, instruction, pcodeOp, pcodeIndex);
        }

        return intraInstructionJumpOccured;
    }


    /**
     * 
     * @param blocks: array pf block terms
     * @param temporaryDefStorage: temporarily stored definitions
     * @param currentBlock: current block term
     * @param instruction: assembly instruction
     * @param pcodeOp: pcode instruction
     * @param pcodeIndex: index of current pcode instruction
     * @param instructionIndex: index of the current assembly instruction
     * 
     * Adds an artificial jump to the previous block if an intra jump occurs and creates a new block.
     */
    protected void handleIntraInstructionJump(ArrayList<Term<Blk>> blocks, ArrayList<Term<Def>> temporaryDefStorage, Blk currentBlock, Instruction instruction, PcodeOp pcodeOp, int pcodeIndex, int instructionIndex) {
        if(instructionIndex > 0 && !(currentBlock.getDefs().size() == 0 && currentBlock.getJmps().size() == 0)) {
            jumpFromPreviousInstructionToNewBlock(blocks, temporaryDefStorage, currentBlock, instruction, pcodeOp, pcodeIndex, instructionIndex);
        } else {
            currentBlock.addMultipleDefs(temporaryDefStorage);
            currentBlock.addJmp(createJmpTerm(instruction, pcodeIndex, pcodeOp, pcodeOp.getMnemonic(), instruction.getAddress()));
        }
        blocks.add(createBlkTerm(instruction.getAddress().toString(), String.valueOf(pcodeIndex + 1)));
        
    }


    /**
     * 
     * @param blocks: array pf block terms
     * @param temporaryDefStorage: temporarily stored definitions
     * @param currentBlock: current block term
     * @param instruction: assembly instruction
     * @param pcodeOp: pcode instruction
     * @param pcodeIndex: index of current pcode instruction
     * @param instructionIndex: index of the current assembly instruction
     * 
     * Adds a jump from the previous instruction to a new intra block
     */
    protected void jumpFromPreviousInstructionToNewBlock(ArrayList<Term<Blk>> blocks, ArrayList<Term<Def>> temporaryDefStorage, Blk currentBlock, Instruction instruction, PcodeOp pcodeOp, int pcodeIndex, int instructionIndex) {
        if(temporaryDefStorage.size() > 0) {
            addJumpToCurrentBlock(currentBlock, instruction.getFallFrom().toString(), instruction.getAddress().toString(), "0");
        } else {
            addJumpToCurrentBlock(currentBlock, instruction.getFallFrom().toString(), instruction.getAddress().toString(), null);
        }
        createNewBlockForIntraInstructionJump(blocks, temporaryDefStorage, instruction, pcodeIndex, pcodeOp);
    }


    /**
     * 
     * @param pcodeOp: pcode instruction
     * @return: boolean whether current pcode instruction is a call
     * 
     * checks whether the current pcode instruction is a call
     */
    protected Boolean isCall(PcodeOp pcodeOp){
        return (pcodeOp.getOpcode() == PcodeOp.CALL || pcodeOp.getOpcode() == PcodeOp.CALLIND);
    }


    /**
     * 
     * @param blocks: array of block terms
     * @param temporaryDefStorage: temporarily stored definitions
     * @param instruction: assembly instruction
     * @param pcodeIndex: index of current pcode instruction
     * @param pcodeOp: pcode instruction
     * 
     * Creates a new block for the pcode instructions of the current assembly instruction and the intra jump
     */
    protected void createNewBlockForIntraInstructionJump(ArrayList<Term<Blk>> blocks, ArrayList<Term<Def>> temporaryDefStorage, Instruction instruction, int pcodeIndex, PcodeOp pcodeOp){
        // Set the starting index of the new block to the first pcode instruction of the assembly instruction
        int nextBlockStartIndex;
        Term<Blk> newBlock;
        if(temporaryDefStorage.size() > 0) {
            nextBlockStartIndex = temporaryDefStorage.get(0).getTerm().getPcodeIndex();
            newBlock = createBlkTerm(instruction.getAddress().toString(), String.valueOf(nextBlockStartIndex));
        } else {
            newBlock = createBlkTerm(instruction.getAddress().toString(), null);
        }
        newBlock.getTerm().addMultipleDefs(temporaryDefStorage);
        newBlock.getTerm().addJmp(createJmpTerm(instruction, pcodeIndex, pcodeOp, pcodeOp.getMnemonic(), instruction.getAddress()));
        blocks.add(newBlock);
    }


    /**
     * 
     * @param currentBlock: current block term
     * @param jmpAddress: address of jump instruction
     * @param gotoAddress: address of where to jump
     * @param suffix: suffix for TID
     * 
     * Adds a jump to the current block.
     */
    protected void addJumpToCurrentBlock(Blk currentBlock, String jmpAddress, String gotoAddress, String suffix) {
        int artificialJmpIndex;
        if(currentBlock.getDefs().size() == 0) {
            artificialJmpIndex = 1;
        } else {
            artificialJmpIndex = currentBlock.getDefs().get(currentBlock.getDefs().size() - 1).getTerm().getPcodeIndex() + 1;
        }
        Tid jmpTid = new Tid(String.format("instr_%s_%s", jmpAddress, artificialJmpIndex), jmpAddress);
        Tid gotoTid;
        if(suffix != null) {
            gotoTid = new Tid(String.format("blk_%s_%s", gotoAddress, suffix), gotoAddress);
        } else {
            gotoTid = new Tid(String.format("blk_%s", gotoAddress), gotoAddress);
        }
        currentBlock.addJmp(new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, "BRANCH", new Label((Tid) gotoTid), artificialJmpIndex)));
    }


    /**
     * 
     * @param block: block term
     * @return: boolean whether block ends on definition
     * 
     * Checks whether the current block term ends on a definition
     */
    protected Boolean lastInstructionIsDef(Term<Blk> block) {
        ArrayList<Term<Jmp>> jumps = block.getTerm().getJmps();
        ArrayList<Term<Def>> defs = block.getTerm().getDefs();

        if(defs.size() > 0 && jumps.size() == 0) {
            return true;
        }
        return false;
    }


    /**
     * 
     * @param blocks: array of block terms
     * @param temporaryDefStorage: temporarily stored definitions
     * @param currentBlock: current block term
     * @param instruction: assembly instruction
     * @param pcodeOp: pcode instruction
     * @param pcodeIndex: index of current pcode instruction
     * 
     * Handles call return pairs by creating a return block and redirecting the call's return to the return block
     */
    protected void handleCallReturnPair(ArrayList<Term<Blk>> blocks, ArrayList<Term<Def>> temporaryDefStorage, Term<Blk> currentBlock, Instruction instruction, PcodeOp pcodeOp, int pcodeIndex) {
        currentBlock.getTerm().addMultipleDefs(temporaryDefStorage);
        Term<Jmp> jump = createJmpTerm(instruction, pcodeIndex, pcodeOp, pcodeOp.getMnemonic(), instruction.getAddress());
        Term<Blk> returnBlock = createBlkTerm(instruction.getAddress().toString(), "r");
        jump.getTerm().getCall().setReturn_(new Label(new Tid(returnBlock.getTid().getId(), returnBlock.getTid().getAddress())));
        currentBlock.getTerm().addJmp(jump);
        blocks.add(returnBlock);
    }


    /**
     * 
     * @param currentBlock: current block term
     * @param instruction: assembly instruction
     * @param pcodeOp: pcode instruction
     * 
     * Redirects the call's return address to the artificially created return block
     */
    protected void redirectCallReturn(Term<Blk> currentBlock, Instruction instruction, PcodeOp pcodeOp) {
        Tid jmpTid = new Tid(String.format("instr_%s_%s_r", instruction.getAddress().toString(), 0), instruction.getAddress().toString());
        Term<Jmp> ret = new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.RETURN, pcodeOp.getMnemonic(), createLabel(pcodeOp.getMnemonic(), pcodeOp, null), 0));
        currentBlock.getTerm().addJmp(ret);
    } 


    /**
     * @param cpuArch: CPU architecture as string
     * @return: new Project
     * 
     * Creates the project object and adds the stack pointer register and program term.
     */
    protected Project createProject() {
        Project project = new Project();
        CompilerSpec comSpec = currentProgram.getCompilerSpec();
        Register stackPointerRegister = comSpec.getStackPointer();
        int stackPointerByteSize = (int) stackPointerRegister.getBitLength() / 8;
        Variable stackPointerVar = new Variable(stackPointerRegister.getName(), stackPointerByteSize, false);
        project.setProgram(program);
        project.setStackPointerRegister(stackPointerVar);
        project.setCpuArch(cpuArch);

        return project;
    }


    /**
     * @return: new Program Term
     * 
     * Creates the project term with an unique TID and adds external symbols.
     */
    protected Term<Program> createProgramTerm() {
        Tid progTid = new Tid(String.format("prog_%s", ghidraProgram.getMinAddress().toString()), ghidraProgram.getMinAddress().toString());
        SymbolTable symTab = ghidraProgram.getSymbolTable();
        return new Term<Program>(progTid, new Program(new ArrayList<Term<Sub>>(), addExternalSymbols(symTab), addEntryPoints(symTab)));
    }


    /**
     * 
     * @param symTab: symbol table
     * @return: list of program entry points
     * 
     * Creates a list of program entry points to add to the program term
     */
    protected ArrayList<Tid> addEntryPoints(SymbolTable symTab) {
        ArrayList<Tid> entryTids = new ArrayList<Tid>();
        AddressIterator entryPoints = symTab.getExternalEntryPointIterator();
        while (entryPoints.hasNext()) {
            Address entry = entryPoints.next();
            entryTids.add(new Tid(String.format("sub_%s", entry.toString()), entry.toString()));
        }

        return entryTids;
    }


    /**
     * 
     * @param symTab: symbol table
     * @return: list of external symbols
     * 
     * Creates a list of external symbols to add to the program term
     */
    protected ArrayList<ExternSymbol> addExternalSymbols(SymbolTable symTab) {
        ArrayList<ExternSymbol> extSym = new ArrayList<ExternSymbol>();
        ArrayList<Symbol> externalSymbols = new ArrayList<Symbol>();
        ArrayList<Symbol> definedSymbols = new ArrayList<Symbol>();
        symTab.getExternalSymbols().forEachRemaining(externalSymbols::add);
        symTab.getDefinedSymbols().forEachRemaining(definedSymbols::add);
        for(Symbol def : definedSymbols) {
            for(Symbol ext : externalSymbols) {
                if(def.getName().equals(ext.getName()) && !def.getAddress().toString().startsWith("EXTERNAL:") && def.getSymbolType() == SymbolType.FUNCTION && notInReferences(def)) {
                    extSym.add(createExternSymbol(def));
                    break;
                }
            }
        }

        return extSym;
    }


    /**
     * 
     * @param sym: external symbol
     * @return: if same symbol name in references
     * 
     * Checks whether the same symbol name is in the references of the current symbol.
     * If so, the current symbol is not internally called by other functions
     */
    protected Boolean notInReferences(Symbol sym) {
        for(Reference ref : sym.getReferences()) {
            if(funcMan.getFunctionContaining(ref.getFromAddress()) != null) {
                if(funcMan.getFunctionContaining(ref.getFromAddress()).getName().equals(sym.getName())) {
                    return false;
                }
            }
        }

        return true;
    }


    /**
     * @param symbol:  External symbol
     * @return: new ExternSymbol
     * 
     * Creates an external symbol with an unique TID, a calling convention and argument objects.
     */
    protected ExternSymbol createExternSymbol(Symbol symbol) {
        Tid tid = new Tid(String.format("sub_%s", symbol.getAddress().toString()), symbol.getAddress().toString());
        ArrayList<Arg> args = createArguments(symbol);
        Boolean noReturn = funcMan.getFunctionAt(symbol.getAddress()).hasNoReturn();
        return new ExternSymbol(tid, symbol.getAddress().toString(), symbol.getName(), funcMan.getDefaultCallingConvention().getName(), args, noReturn);

    }


    /**
     * @param def:     Defined symbol
     * @return: true if referencing function is thunk, else false
     * 
     * Checks if current external symbol is referenced by a Thunk Function.
     * If so, the Thunk Function is the internally called function.
     */
    protected Boolean isThunkFunctionRef(Symbol def) {
        Reference[] refs = def.getReferences();
        if(refs.length == 0) {
            return false;
        }
        Address refAddr = def.getReferences()[0].getFromAddress();
        return funcMan.getFunctionContaining(refAddr) != null && funcMan.getFunctionContaining(refAddr).isThunk();
    }


    protected Boolean hasVoidReturn(Function func) {
        return func.hasNoReturn() || func.getReturn().getDataType().getName().equals("void");
    }


    /**
     * @param symbol:  Symbol used to get corresponding function
     * @return: new Arg ArrayList
     * 
     * Creates Arguments for the ExternSymbol object.
     */
    protected ArrayList<Arg> createArguments(Symbol symbol) {
        ArrayList<Arg> args = new ArrayList<Arg>();
        Function func = funcMan.getFunctionAt(symbol.getAddress());
        Parameter[] params = func.getParameters();
        for (Parameter param : params) {
            args.add(specifyArg(param));
        }
        if (!hasVoidReturn(func)) {
            args.add(new Arg(createVariable(func.getReturn().getFirstStorageVarnode(), true), "OUTPUT"));
        }

        return args;
    }


    /**
     * @param param: Function parameter
     * @return: new Arg
     * 
     * Specifies if the argument is a stack variable or a register.
     */
    protected Arg specifyArg(Parameter param) {
        Arg arg = new Arg();
        if (param.isStackVariable()) {
            Variable stackVar = createVariable(param.getFirstStorageVarnode(), true);
            arg.setLocation(new Expression("LOAD", stackVar));
        } else if (param.isRegisterVariable()) {
            arg.setVar(createVariable(param.getFirstStorageVarnode(), true));
        }
        arg.setIntent("INPUT");

        return arg;
    }


    /**
     * @param func: Ghidra function object
     * @return: new Sub Term
     * 
     * Creates a Sub Term with an unique TID consisting of the prefix sub and its entry address.
     */
    protected Term<Sub> createSubTerm(Function func) {
        Tid subTid = new Tid(String.format("sub_%s", func.getEntryPoint().toString()), func.getEntryPoint().toString());
        return new Term<Sub>(subTid, new Sub(func.getName(), func.getBody()));
    }


    /**
     * @param block: Instruction block
     * @return: new Blk Term
     * 
     * Creates a Blk Term with an unique TID consisting of the prefix blk and its entry address.
     */
    protected Term<Blk> createBlkTerm(String tidAddress, String suffix) {
        Tid blkTid;
        if(suffix != null) {
            blkTid = new Tid(String.format("blk_%s_%s", tidAddress, suffix), tidAddress);
        } else {
            blkTid = new Tid(String.format("blk_%s", tidAddress), tidAddress);
        }
        return new Term<Blk>(blkTid, new Blk());
    }


    /**
     * @param instr:      Assembly instruction
     * @param pCodeCount: Pcode index in current block
     * @param pcodeOp:    Pcode instruction
     * @param mnemonic:   Pcode instruction mnemonic
     * @param instrAddr:  Assembly instruction address
     * @return: new Jmp Term
     * 
     * Creates a Jmp Term with an unique TID consisting of the prefix jmp, its instruction address and the index of the pcode in the block.
     * Depending on the instruction, it either has a goto label, a goto label and a condition or a call object.
     */
    protected Term<Jmp> createJmpTerm(Instruction instr, int pCodeCount, PcodeOp pcodeOp, String mnemonic, Address instrAddr) {
        Tid jmpTid = new Tid(String.format("instr_%s_%s", instrAddr.toString(), pCodeCount), instrAddr.toString());
        if (mnemonic.equals("CBRANCH")) {
            return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, mnemonic, createLabel(mnemonic, pcodeOp, null), createVariable(pcodeOp.getInput(1), false), pCodeCount));
        } else if (mnemonic.equals("BRANCH") || mnemonic.equals("BRANCHIND")) {
            return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, mnemonic, createLabel(mnemonic, pcodeOp, null), pCodeCount));
        } else if (mnemonic.equals("RETURN")) {
            return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.RETURN, mnemonic, createLabel(mnemonic, pcodeOp, null), pCodeCount));
        }

        Term<Jmp> call = new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.CALL, mnemonic, createCall(instr, mnemonic, pcodeOp), pCodeCount));
        call = checkIfCallindResolved(call);

        return call;
    }


    /**
     * 
     * @param call: indirect call
     * @return: direkt call or indirekt call
     * 
     * Checks whether the indirect call could have been resolved and casts it into a direct call
     */
    protected Term<Jmp> checkIfCallindResolved(Term<Jmp> call) {
        if (call.getTerm().getMnemonic().equals("CALLIND")) {
            if (call.getTerm().getCall().getTarget().getIndirect() == null) {
                call.getTerm().setMnemonic("CALL");
            }
        }

        return call;
    }


    /**
     * @param pCodeCount: Pcode index in current block
     * @param pcodeOp:    Pcode instruction
     * @param instrAddr:  Assembly instruction address
     * @return: new Def Term
     * 
     * Creates a Def Term with an unique TID consisting of the prefix def, its instruction address and the index of the pcode in the block.
     */
    protected Term<Def> createDefTerm(int pcodeIndex, PcodeOp pcodeOp, Address instrAddr) {
        Tid defTid = new Tid(String.format("instr_%s_%s", instrAddr.toString(), pcodeIndex), instrAddr.toString());
        if (pcodeOp.getMnemonic().equals("STORE")) {
            return new Term<Def>(defTid, new Def(createExpression(pcodeOp), pcodeIndex));
            // cast copy instructions that have address outputs into store instructions
        } else if (pcodeOp.getMnemonic().equals("COPY") && pcodeOp.getOutput().isAddress()) {
            return new Term<Def>(defTid, new Def(new Expression("STORE", null, createVariable(pcodeOp.getOutput(), false), createVariable(pcodeOp.getInput(0), false)), pcodeIndex));
        }
        return new Term<Def>(defTid, new Def(createVariable(pcodeOp.getOutput(), false), createExpression(pcodeOp), pcodeIndex));
    }


    /**
     * @param node: Varnode source for Variable
     * @return: new Variable
     * 
     * Set register name based on being a register, virtual register, constant or ram address.
     * In case it is a virtual register, prefix the name with $U.
     * In case it is a constant, remove the const prefix from the constant.
     */
    protected Variable createVariable(Varnode node, Boolean isArgument) {
        Variable var = new Variable();
        if (node.isRegister()) {
            String mnemonic = getRegisterMnemonic(node);
            if(isArgument && mnemonic.equals("AL")){
                return castToFullRegister(var, node);
            }
            var.setName(mnemonic);
            var.setIsVirtual(false);
        } else if (node.isUnique()) {
            var.setName(renameVirtualRegister(node.getAddress().toString()));
            var.setIsVirtual(true);
        } else if (node.isConstant()) {
            var.setValue(removeConstantPrefix(node.getAddress().toString()));
            var.setIsVirtual(false);
        } else if (node.isAddress()) {
            var.setAddress(node.getAddress().toString());
            var.setIsVirtual(false);
        } else if (node.isFree()) {
            var.setAddress(removeStackPrefix(node.getAddress().toString()));
            var.setIsVirtual(false);
        }

        var.setSize(node.getSize());

        return var;
    }


    /**
     * 
     * @param var: register variable
     * @param node: varnode containing half register
     * @return: full register variable
     * 
     * Casts half registers to full registers
     */
    protected Variable castToFullRegister(Variable var, Varnode node) {
        if(cpuArch.equals("x86_32")) {
            var.setName("EAX");
            var.setSize(4);
        } else {
            var.setName("RAX");
            var.setSize(8);
        }
        var.setIsVirtual(false);
        return var;
    }


    /**
     * @param pcodeOp: Pcode instruction
     * @return: new Epxression
     * 
     * Create an Expression using the input varnodes of the pcode instruction.
     */
    protected Expression createExpression(PcodeOp pcodeOp) {
        String mnemonic = pcodeOp.getMnemonic();
        List<Variable> in = new ArrayList<Variable>();

        for (Varnode input : pcodeOp.getInputs()) {
            in.add(createVariable(input, false));
        }

        int inputLen = in.size();

        if (inputLen == 1) {
            return new Expression(mnemonic, in.get(0));
        } else if (inputLen == 2) {
            return new Expression(mnemonic, in.get(0), in.get(1));
        } else {
            return new Expression(mnemonic, in.get(0), in.get(1), in.get(2));
        }
    }


    /**
     * @param mnemonic:    Pcode instruction mnemonic
     * @param pcodeOp:     Pcode instruction
     * @param fallThrough: fallThrough address of branch/call
     * @return: new Label
     * 
     * Create a Label based on the branch instruction. For indirect branches and calls, it consists of a Variable, for calls of a sub TID
     * and for branches of a blk TID.
     */
    protected Label createLabel(String mnemonic, PcodeOp pcodeOp, Address fallThrough) {
        Label jumpLabel;
        if (fallThrough == null) {
            switch(mnemonic) {
                case "CALLIND": 
                    jumpLabel = handleLabelsForIndirectCalls(pcodeOp);
                    break;
                case "BRANCHIND":
                case "RETURN":
                    jumpLabel = new Label((Variable) createVariable(pcodeOp.getInput(0), false));
                    break;
                case "CALL":
                case "CALLOTHER":
                    jumpLabel = new Label((Tid) new Tid(String.format("sub_%s", pcodeOp.getInput(0).getAddress().toString()), pcodeOp.getInput(0).getAddress().toString()));
                    break;
                default:
                    jumpLabel = new Label((Tid) new Tid(String.format("blk_%s", pcodeOp.getInput(0).getAddress().toString()), pcodeOp.getInput(0).getAddress().toString()));
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
    protected Label handleLabelsForIndirectCalls(PcodeOp pcodeOp) {
        Tid subTid = getTargetTid(pcodeOp.getInput(0));
        if (subTid != null) {
            return new Label(subTid);
        }
        return new Label((Variable) createVariable(pcodeOp.getInput(0), false));
    }


    /**
     * 
     * @param target: target address of indirect jump
     * @return: target id of symbol
     * 
     * Resolves the target id for an indirect jump
     */
    protected Tid getTargetTid(Varnode target) {
        if (!target.isRegister() && !target.isUnique()) {
            Reference[] referenced = ghidraProgram.getReferenceManager().getReferencesFrom(target.getAddress());
            if(referenced.length != 0) {
                for (ExternSymbol symbol : program.getTerm().getExternSymbols()) {
                    if (symbol.getAddress().equals(referenced[0].getToAddress().toString())) {
                        return symbol.getTid();
                    }
                }
            }
        }
        return null;
    }


    /**
     * @param instr:    Assembly instruction
     * @param mnemonic: Pcode instruction mnemonic
     * @param pcodeOp:  Pcode instruction
     * @return: new Call
     * 
     * Creates a Call object, using a target and return Label.
     */
    protected Call createCall(Instruction instr, String mnemonic, PcodeOp pcodeOp) {
        if(mnemonic.equals("CALLOTHER")) {
            String callString = ghidraProgram.getLanguage().getUserDefinedOpName((int) pcodeOp.getInput(0).getOffset());
            return new Call(createLabel(mnemonic, pcodeOp, null), createLabel(mnemonic, pcodeOp, instr.getFallThrough()), callString);
        }
        return new Call(createLabel(mnemonic, pcodeOp, null), createLabel(mnemonic, pcodeOp, instr.getFallThrough()));
    }


    /**
     * @param address: Virtual register address
     * @return: Prefixed virtual register naem
     * 
     * Prefixes virtual register with $U.
     */
    protected String renameVirtualRegister(String address) {
        return "$U" + address.replaceFirst("^(unique:0+(?!$))", "");
    }


    /**
     * @param node: Register Varnode
     * @return: Register mnemonic
     * 
     * Gets register mnemonic.
     */
    protected String getRegisterMnemonic(Varnode node) {
        return context.getRegister(node).getName();
    }


    /**
     * @param constant: Constant value
     * @return: Constant value without prefix
     * 
     * Removes the consts prefix from the constant.
     */
    protected String removeConstantPrefix(String constant) {
        return constant.replaceFirst("^(const:)", "");
    }


    /**
     * 
     * @param param: stack parameter
     * @return: stack parameter without stack prefix
     * 
     * Removes stack prefix from stack parameter. e.g. Stack[0x4] => 0x4
     */
    protected String removeStackPrefix(String param) {
        Matcher matcher = Pattern.compile("^Stack\\[(0x\\d)\\]$").matcher(param);
        if(matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }

}
