import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.StreamSupport;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.EnumUtils;

import bil.*;
import term.*;
import internal.*;
import internal.PcodeBlockData;
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
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SymbolTable;
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
    SymbolTable symTab;
    HashMap<String, Tid> functionEntryPoints;
    HashMap<String, ExternSymbol> externalSymbolMap;
    ghidra.program.model.listing.Program ghidraProgram;
    VarnodeContext context;
    String cpuArch;

    Set<String> binOps = EnumUtils.getEnumMap(ExecutionType.BinOpType.class).keySet();
    Set<String> unOps = EnumUtils.getEnumMap(ExecutionType.UnOpType.class).keySet();
    Set<String> casts = EnumUtils.getEnumMap(ExecutionType.CastType.class).keySet();


    /**
     * 
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

        symTab = ghidraProgram.getSymbolTable();
        externalSymbolMap = new HashMap<String, ExternSymbol>();
        createExternalSymbolMap(symTab);
        program = createProgramTerm();
        functionEntryPoints = new HashMap<String, Tid>();
        setFunctionEntryPoints();
        Project project = createProject();
        program = iterateFunctions(simpleBM, listing);
        program.getTerm().setExternSymbols(new ArrayList<ExternSymbol>(externalSymbolMap.values()));

        String jsonPath = getScriptArgs()[0];
        Serializer ser = new Serializer(project, jsonPath);
        ser.serializeProject();
        TimeUnit.SECONDS.sleep(3);

    }


    /**
     * Adds all entry points of internal and external function to a global hash map
     * This will later speed up the cast of indirect Calls.
     */
    protected void setFunctionEntryPoints() {
        // Add internal function addresses
        for(Function func : funcMan.getFunctions(true)) {
            String address = func.getEntryPoint().toString();
            functionEntryPoints.put(address, new Tid(String.format("sub_%s", address), address));
        }

        // Add thunk addresses for external functions
        for(ExternSymbol sym : externalSymbolMap.values()){
            for(String address : sym.getAddresses()) {
                functionEntryPoints.put(address, sym.getTid());
            }
        }
    }


    /**
     * 
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
     * 
     * @param simpleBM: Simple Block Model to iterate over blocks
     * @param listing:  Listing to get assembly instructions
     * @return: Processed Program Term
     * 
     * Iterates over functions to create sub terms and calls the block iterator to add all block terms to each subroutine.
     */
    protected Term<Program> iterateFunctions(SimpleBlockModel simpleBM, Listing listing) {
        FunctionIterator functions = funcMan.getFunctions(true);
        for (Function func : functions) {
            if (!externalSymbolMap.containsKey(func.getName())){
                Term<Sub> currentSub = createSubTerm(func);
                currentSub.getTerm().setBlocks(iterateBlocks(currentSub, simpleBM, listing));
                program.getTerm().addSub(currentSub);
            }
        }

        return program;
    }


    /**
     * 
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
     * 
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
                addBranchToCurrentBlock(lastBlockTerm.getTerm(), instrAddress, destinationAddress);
            }
        }
    }


    /**
     * 
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
     * 
     * @param block:     Blk Term to be filled with instructions
     * @param listing:   Assembly instructions
     * @param codeBlock: codeBlock for retrieving instructions
     * @return: new array of Blk Terms
     * 
     * Iterates over assembly instructions and processes each of the pcode blocks.
     * Handles empty block by adding a jump Term with fallthrough address
     */
    protected ArrayList<Term<Blk>> iterateInstructions(Term<Blk> block, Listing listing, CodeBlock codeBlock) {
        PcodeBlockData.instructionIndex = 0;
        InstructionIterator instructions = listing.getInstructions(codeBlock, true);
        PcodeBlockData.numberOfInstructionsInBlock = StreamSupport.stream(listing.getInstructions(codeBlock, true).spliterator(), false).count();
        PcodeBlockData.blocks = new ArrayList<Term<Blk>>();
        PcodeBlockData.blocks.add(block);

        for (Instruction instr : instructions) {
            PcodeBlockData.instruction = instr;
            analysePcodeBlockOfAssemblyInstruction();
            PcodeBlockData.instructionIndex++;
        }

        if (PcodeBlockData.blocks.get(0).getTerm().getDefs().isEmpty() && PcodeBlockData.blocks.get(0).getTerm().getJmps().isEmpty()) {
            handleEmptyBlock(codeBlock);
        }

        return PcodeBlockData.blocks;
    }


    /**
     * 
     * @param codeBlock: Current empty block
     * @return New jmp term containing fall through address
     * 
     * Adds fallthrough address jump to empty block if available
     */
    protected void handleEmptyBlock(CodeBlock codeBlock) {
        try {
            CodeBlockReferenceIterator destinations = codeBlock.getDestinations(getMonitor());
            if(destinations.hasNext()) {
                Tid jmpTid = new Tid(String.format("instr_%s_%s", codeBlock.getFirstStartAddress().toString(), 0), codeBlock.getFirstStartAddress().toString());
                Tid gotoTid = new Tid();
                String destAddr = destinations.next().getDestinationBlock().getFirstStartAddress().toString();
                gotoTid.setId(String.format("blk_%s", destAddr));
                gotoTid.setAddress(destAddr);
                PcodeBlockData.blocks.get(0).getTerm().addJmp(new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, "BRANCH", new Label((Tid) gotoTid), 0)));
            }
        } catch (CancelledException e) {
            System.out.printf("Could not retrieve destinations for block at: %s\n", codeBlock.getFirstStartAddress().toString());
        }
    }


    /**
     * 
     * Checks whether the assembly instruction is a nop instruction and adds a jump to the block.
     * Checks whether a jump occured within a ghidra generated pcode block and fixes the control flow
     * by adding missing jumps between artificially generated blocks.
     * Checks whether an instruction is in a delay slot and, if so, ignores it 
     * as Ghidra already includes the instruction before the jump
     */
    protected void analysePcodeBlockOfAssemblyInstruction() {
        PcodeBlockData.ops = PcodeBlockData.instruction.getPcode(true);
        if(PcodeBlockData.instruction.isInDelaySlot()) {
            return;
        }
        if(PcodeBlockData.ops.length == 0) {
            addBranchToCurrentBlock(PcodeBlockData.blocks.get(PcodeBlockData.blocks.size()-1).getTerm(), PcodeBlockData.instruction.getAddress().toString(), PcodeBlockData.instruction.getFallThrough().toString());
            if(PcodeBlockData.instructionIndex < PcodeBlockData.numberOfInstructionsInBlock - 1) {
                PcodeBlockData.blocks.add(createBlkTerm(PcodeBlockData.instruction.getFallThrough().toString(), null));
            }
            return;
        }

        PcodeBlockData.temporaryDefStorage = new ArrayList<Term<Def>>();
        Boolean intraInstructionJumpOccured = iteratePcode();

        fixControlFlowWhenIntraInstructionJumpOccured(intraInstructionJumpOccured);

        if(!PcodeBlockData.temporaryDefStorage.isEmpty()) {
            PcodeBlockData.blocks.get(PcodeBlockData.blocks.size() - 1).getTerm().addMultipleDefs(PcodeBlockData.temporaryDefStorage);
        }
    }


    /**
     * 
     * @return: indicator if jump occured within pcode block
     * 
     * Iterates over the Pcode instructions of the current assembly instruction.
     */
    protected Boolean iteratePcode() {
        int numberOfPcodeOps = PcodeBlockData.ops.length;
        Boolean intraInstructionJumpOccured = false;
        PcodeBlockData.pcodeIndex = 0;
        for(PcodeOp op : PcodeBlockData.ops) {
            PcodeBlockData.pcodeOp = op;
            String mnemonic = PcodeBlockData.pcodeOp.getMnemonic();
            if (this.jumps.contains(mnemonic) || PcodeBlockData.pcodeOp.getOpcode() == PcodeOp.UNIMPLEMENTED) {
                intraInstructionJumpOccured = processJump(mnemonic, numberOfPcodeOps);
            } else {
                PcodeBlockData.temporaryDefStorage.add(createDefTerm());
            }
            PcodeBlockData.pcodeIndex++;
        }

        return intraInstructionJumpOccured;
    }


    /**
     * 
     * @param intraInstructionJumpOccured: indicator if jump occured within pcode block
     * 
     * fixes the control flow by adding missing jumps between artificially generated blocks.
     */
    protected void fixControlFlowWhenIntraInstructionJumpOccured(Boolean intraInstructionJumpOccured) {
        // A block is split when a Pcode Jump Instruction occurs in the PcodeBlock. 
        // A jump is added to the end of the split block to the pcode block of the next assembly instruction
        if(intraInstructionJumpOccured) {
            Term<Blk> lastBlock = PcodeBlockData.blocks.get(PcodeBlockData.blocks.size() - 1);
            addMissingJumpAfterInstructionSplit(lastBlock);
        }
    }


    /**
     * 
     * @param lastBlock: last block before split
     * 
     * Adds a missing jump after a Ghidra generated block has been split to maintain the control flow
     * between the blocks
     */
    protected void addMissingJumpAfterInstructionSplit(Term<Blk> lastBlock) {
        lastBlock.getTerm().addMultipleDefs(PcodeBlockData.temporaryDefStorage);
        addBranchToCurrentBlock(lastBlock.getTerm(), PcodeBlockData.instruction.getAddress().toString(), PcodeBlockData.instruction.getFallThrough().toString());
        PcodeBlockData.blocks.add(createBlkTerm(PcodeBlockData.instruction.getFallThrough().toString(), null));
        PcodeBlockData.temporaryDefStorage.clear();
    }


    /**
     *
     * @param mnemonic: pcode mnemonic
     * @param numberOfPcodeOps: number of pcode instruction in pcode block
     * @return: indicator whether a jump occured inside a pcode block
     * 
     * Processes jump pcode instruction by checking where it occurs.
     * Distinguishes between jumps inside a pcode block and jumps at the end of a pcode block
     */
    protected Boolean processJump(String mnemonic, int numberOfPcodeOps) {

        Term<Blk> currentBlock = PcodeBlockData.blocks.get(PcodeBlockData.blocks.size() - 1);

        if(PcodeBlockData.pcodeIndex < numberOfPcodeOps - 1) {
            return processJumpInPcodeBlock(mnemonic, numberOfPcodeOps, currentBlock);
        }

        processJumpAtEndOfPcodeBlocks(mnemonic, numberOfPcodeOps, currentBlock);
        return false;
    }


    /**
     * 
     * @param mnemonic: pcode mnemonic
     * @param numberOfPcodeOps: number of pcode instruction in pcode block
     * @param currentBlock: current block term
     * 
     * Process jumps at the end of pcode blocks
     * If it is a return block, the call return address is changed to the current block
     */
    protected void processJumpAtEndOfPcodeBlocks(String mnemonic, int numberOfPcodeOps, Term<Blk> currentBlock) {
        // Case 1: jump at the end of pcode group but not end of ghidra generated block. Create a block for the next assembly instruction.
        if(PcodeBlockData.instructionIndex < PcodeBlockData.numberOfInstructionsInBlock - 1 && PcodeBlockData.instruction.getDelaySlotDepth() == 0) {
            PcodeBlockData.blocks.add(createBlkTerm(PcodeBlockData.instruction.getFallThrough().toString(), null));
        }
        // Case 2: jmp at last pcode op at last instruction in ghidra generated block
        // If Case 1 is true, the 'currentBlk' will be the second to last block as the new block is for the next instruction
        if(PcodeBlockData.pcodeOp.getOpcode() == PcodeOp.RETURN && currentBlock.getTid().getId().endsWith("_r")) {
            redirectCallReturn(currentBlock);
        }
        currentBlock.getTerm().addMultipleDefs(PcodeBlockData.temporaryDefStorage);
        currentBlock.getTerm().addMultipleJumps(createJmpTerm(false));
        PcodeBlockData.temporaryDefStorage.clear();
    }


    /**
     * 
     * @param mnemonic: pcode mnemonic
     * @param numberOfPcodeOps: number of pcode instruction in pcode block
     * @param currentBlock: current block term
     * @return: indicator whether a jump occured inside a pcode block
     * 
     * Processes a jump inside a pcode block and distinguishes between intra jumps and call return pairs.
     */
    protected Boolean processJumpInPcodeBlock(String mnemonic, int numberOfPcodeOps, Term<Blk> currentBlock) {
        Boolean intraInstructionJumpOccured = false;
        if(!isCall()) {
            intraInstructionJumpOccured = true;
            handleIntraInstructionJump(currentBlock.getTerm());
        } else {
            handleCallReturnPair(currentBlock);
        }
        PcodeBlockData.temporaryDefStorage.clear();

        return intraInstructionJumpOccured;
    }


    /**
     * 
     * @param currentBlock: current block term
     * 
     * Adds an artificial jump from the previous instructions to the current instruction if an intra jump occurs.
     * This is done to isolate the current defs and jumps in an exclusive block.
     * The Jump is not added if the instruction is the first of the subroutine or if no defs and jumps have been added yet.
     * This might be the case when the current instruction is only preceded by a nop instruction.
     * 
     * In case an artificial jump has to be added, a new block has to be created for the instruction with the intra jump so that
     * the previous jump has a valid target TID.
     * 
     * e.g. This example shows one basic block generated by Ghidra which split into 4 basic blocks for proper analysis. 
     * It also includes the case where a jump from the previous assembly instruction had to be added.
     * Each individual assembly instruction is denoted with the [In] keyword and blocks are separated by dashed lines.
     * Keep in mind that the target rows for the branches are only placeholders for the actual target TIDs.
     * 
     * 1. [In]  ...                                         ...
     * 2.       RDI = COPY RDX                              RDI = COPY RDX
     * 3.                                                   BRANCH [row 5.]
     * 4.                                                   ---------------
     * 5. [In]  $U2360:1 = INT_EQUAL RCX, 0:8               $U2360:1 = INT_EQUAL RCX, 0:8
     * 6.       CBRANCH *[ram]0x1006e1:8, $U2360            CBRANCH *[ram]0x1006e1:8, $U2360
     * 7.                                                   BRANCH [row 9.]
     * 8.                                                   ---------------
     * 9.       RCX = INT_SUB RCX, 1:8                      RCX = INT_SUB RCX, 1:8
     * 10.      ...                                 ---->   ...
     * 11.      $U2380:1 = BOOL_NEGATE ZF                   $U2380:1 = BOOL_NEGATE ZF
     * 11.      CBRANCH *[ram]0x1006df:8, $U2380            CBRANCH *[ram]0x1006df:8, $U2380
     * 12.                                                  BRANCH [row 14.]
     * 13.                                                  ---------------
     * 14. [In] RAX = COPY RCX                              RAX = COPY RCX
     * 15.      ...                                         ...
     */
    protected void handleIntraInstructionJump(Blk currentBlock) {
        if(PcodeBlockData.instructionIndex > 0 && !(currentBlock.getDefs().size() == 0 && currentBlock.getJmps().size() == 0)) {
            addBranchToCurrentBlock(currentBlock, PcodeBlockData.instruction.getFallFrom().toString(), PcodeBlockData.instruction.getAddress().toString());
            createNewBlockForIntraInstructionJump();
        } else {
            currentBlock.addMultipleDefs(PcodeBlockData.temporaryDefStorage);
            currentBlock.addMultipleJumps(createJmpTerm(true));
        }
        // Create block for the pcode instructions after the intra jump !Not for the next assembly instruction!
        // Check whether the number of jumps is equal to 2, i.e. a pair of CBRANCH, BRANCH was created. If so, increase the pcodeIndex by 1
        // so that the next intr block has the correct index.
        if(PcodeBlockData.blocks.get(PcodeBlockData.blocks.size() - 1).getTerm().getJmps().size() == 2) {
            PcodeBlockData.pcodeIndex +=1;
        }
        PcodeBlockData.blocks.add(createBlkTerm(PcodeBlockData.instruction.getAddress().toString(), String.valueOf(PcodeBlockData.pcodeIndex + 1)));
        
    }


    /**
     * 
     * @return: boolean whether current pcode instruction is a call
     * 
     * checks whether the current pcode instruction is a call
     */
    protected Boolean isCall(){
        switch(PcodeBlockData.pcodeOp.getOpcode()) {
            case PcodeOp.CALL:
            case PcodeOp.CALLIND:
            case PcodeOp.CALLOTHER:
                return true;
            default:
                return false;
        }
    }


    /**
     * 
     * Creates a new block for the pcode instructions of the current assembly instruction and the intra jump
     */
    protected void createNewBlockForIntraInstructionJump(){
        Term<Blk> newBlock;
        // If an assembly instruction's pcode block is split into multiple blocks, the blocks' TIDs have to be distinguished by pcode index as they share the same instruction address
        if(PcodeBlockData.temporaryDefStorage.size() > 0) {
            int nextBlockStartIndex = PcodeBlockData.temporaryDefStorage.get(0).getTerm().getPcodeIndex();
            if(nextBlockStartIndex == 0) {
                newBlock = createBlkTerm(PcodeBlockData.instruction.getAddress().toString(), null);
            } else {
                newBlock = createBlkTerm(PcodeBlockData.instruction.getAddress().toString(), String.valueOf(nextBlockStartIndex));
            }
        } else {
            newBlock = createBlkTerm(PcodeBlockData.instruction.getAddress().toString(), null);
        }
        newBlock.getTerm().addMultipleDefs(PcodeBlockData.temporaryDefStorage);
        newBlock.getTerm().addMultipleJumps(createJmpTerm(true));
        PcodeBlockData.blocks.add(newBlock);
    }


    /**
     * 
     * @param currentBlock: current block term
     * @param jmpAddress: address of jump instruction
     * @param gotoAddress: address of where to jump
     * 
     * Adds a branch to the current block.
     * The jump index for the instruction will be the pcode index +1
     */
    protected void addBranchToCurrentBlock(Blk currentBlock, String jumpSiteAddress, String gotoAddress) {
        int artificialJmpIndex = 1;
        if(currentBlock.getDefs().size() > 0) {
            artificialJmpIndex = currentBlock.getDefs().get(currentBlock.getDefs().size() - 1).getTerm().getPcodeIndex() + 1;
        }
        Tid jmpTid = new Tid(String.format("instr_%s_%s", jumpSiteAddress, artificialJmpIndex), jumpSiteAddress);
        Tid gotoTid = new Tid(String.format("blk_%s", gotoAddress), gotoAddress);
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
     * @param currentBlock: current block term
     * 
     * Handles call return pairs by creating a return block and redirecting the call's return to the return block
     */
    protected void handleCallReturnPair(Term<Blk> currentBlock) {
        currentBlock.getTerm().addMultipleDefs(PcodeBlockData.temporaryDefStorage);
        Term<Jmp> jump = createJmpTerm(false).get(0);
        Term<Blk> returnBlock = createBlkTerm(PcodeBlockData.instruction.getAddress().toString(), "r");
        jump.getTerm().getCall().setReturn_(new Label(new Tid(returnBlock.getTid().getId(), returnBlock.getTid().getAddress())));
        currentBlock.getTerm().addJmp(jump);
        PcodeBlockData.blocks.add(returnBlock);
    }


    /**
     * 
     * @param currentBlock: current block term
     * 
     * Redirects the call's return address to the artificially created return block
     */
    protected void redirectCallReturn(Term<Blk> currentBlock) {
        Tid jmpTid = new Tid(String.format("instr_%s_%s_r", PcodeBlockData.instruction.getAddress().toString(), 0), PcodeBlockData.instruction.getAddress().toString());
        Term<Jmp> ret = new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.RETURN, PcodeBlockData.pcodeOp.getMnemonic(), createLabel(null), 0));
        currentBlock.getTerm().addJmp(ret);
    } 


    /**
     * 
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
        try {
            HashMap<String, RegisterConvention> conventions = new HashMap<String, RegisterConvention>();
            ParseCspecContent.parseSpecs(ghidraProgram, conventions);
            addParameterRegister(conventions);
            project.setRegisterConvention(new ArrayList<RegisterConvention>(conventions.values()));
        } catch (FileNotFoundException e) {
            System.out.println(e);
        }

        return project;
    }


    /**
     * @return: new Program Term
     * 
     * Creates the project term with an unique TID and adds external symbols.
     */
    protected Term<Program> createProgramTerm() {
        Tid progTid = new Tid(String.format("prog_%s", ghidraProgram.getMinAddress().toString()), ghidraProgram.getMinAddress().toString());
        return new Term<Program>(progTid, new Program(new ArrayList<Term<Sub>>(), addEntryPoints(symTab)));
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
     * 
     * Creates a map of external symbols to add to the program term
     */
    protected void createExternalSymbolMap(SymbolTable symTab) {
        HashMap<String, ArrayList<Function>> symbolMap = new HashMap<String, ArrayList<Function>>();
        funcMan.getExternalFunctions().forEach(func -> {
            ArrayList<Function> thunkFuncs = new ArrayList<Function>();
            getThunkFunctions(func, thunkFuncs);
            if(thunkFuncs.size() > 0) {
                for(Function thunk : thunkFuncs) {
                    addToSymbolMap(symbolMap, thunk);
                }
            } else {
                addToSymbolMap(symbolMap, func);
            }
        });

        createExternalSymbols(symbolMap);
    }


    /**
     * 
     * @param func: Function for which thunk functions are to be found
     * @param thunkFuncs: List of found thunk functions
     * 
     * Recursively find thunk functions in symbol chain
     */
    protected void getThunkFunctions(Function func, ArrayList<Function> thunkFuncs) {
        Address[] thunks = func.getFunctionThunkAddresses();
        if(thunks != null) {
            for(Address thunkAddr : thunks) {
                Function thunkFunction = getFunctionAt(thunkAddr);
                thunkFuncs.add(funcMan.getFunctionAt(thunkAddr));
                getThunkFunctions(thunkFunction, thunkFuncs);
            }
        }
    }


    /**
     * 
     * @param symbolMap: Maps symbol names to multiple function declarations
     * @param func: Function to be added to symbol map
     * 
     * Either adds a function to a given symbol name or creates a new entry in the symbol map
     */
    protected void addToSymbolMap(HashMap<String, ArrayList<Function>> symbolMap, Function func) {
        if(symbolMap.containsKey(func.getName())) {
            symbolMap.get(func.getName()).add(func);
        } else {
            symbolMap.put(func.getName(), new ArrayList<Function>(){{add(func);}});
        }
    }


    /**
     * 
     * @param func: function to get arguments
     * @return: if same symbol name in references
     * 
     * Checks whether the same symbol name is in the references of the current symbol.
     * If so, the current symbol is not internally called by other functions
     * 
     * e.g. some_function() -> system() -> system() -> external_system()
     * 
     * In this Example some_function() only calls the leftmost system() function 
     * and if we have the one in the middle as parameter of notInReferences(),
     * the leftmost will be in the references. As a consequence, the middle function
     * of the chain is not taken into the external symbol list as it is not called 
     * by some_function().
     * 
     */
    protected Boolean notInReferences(Function func) {
        for(Function calling : func.getCallingFunctions(getMonitor())) {
            if(calling.getName().equals(func.getName())) {
                return false;
            }
        }

        return true;
    }


    /**
     * @param symbolMap: External symbol map
     * 
     * Creates external symbol map with an unique TID, a calling convention and argument objects.
     */
    protected void createExternalSymbols(HashMap<String, ArrayList<Function>> symbolMap) {
        for(Map.Entry<String, ArrayList<Function>> functions : symbolMap.entrySet()) {
            ExternSymbol extSym = new ExternSymbol();
            extSym.setName(functions.getKey());
            for(Function func : functions.getValue()) {
                if(notInReferences(func)) {
                    extSym.setTid(new Tid(String.format("sub_%s", func.getEntryPoint().toString()), func.getEntryPoint().toString()));
                    extSym.setNoReturn(func.hasNoReturn());
                    extSym.setArguments(createArguments(func));
                    extSym.setCallingConvention(funcMan.getDefaultCallingConvention().toString());
                }
                if(!func.isExternal()) {
                    extSym.getAddresses().add(func.getEntryPoint().toString());
                }
            }
            externalSymbolMap.put(functions.getKey(), extSym);
        }

    }


    protected Boolean hasVoidReturn(Function func) {
        return func.hasNoReturn() || func.getReturn().getDataType().getName().equals("void");
    }


    /**
     * @param func: function to get arguments
     * @return: new Arg ArrayList
     * 
     * Creates Arguments for the ExternSymbol object.
     */
    protected ArrayList<Arg> createArguments(Function func) {
        ArrayList<Arg> args = new ArrayList<Arg>();
        Parameter[] params = func.getParameters();
        for (Parameter param : params) {
            args.add(specifyArg(param));
        }
        if (!hasVoidReturn(func)) {
            for(Varnode node : func.getReturn().getVariableStorage().getVarnodes()) {
                args.add(new Arg(checkForParentRegister(node), "OUTPUT"));
            }
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
            Variable stackVar = createVariable(param.getFirstStorageVarnode());
            arg.setLocation(new Expression("LOAD", stackVar));
        } else if (param.isRegisterVariable()) {
            arg.setVar(checkForParentRegister(param.getFirstStorageVarnode()));
        }
        arg.setIntent("INPUT");

        return arg;
    }


    /**
     * 
     * @param var: register variable
     * @param node: varnode containing half register
     * @param isArgument: check if register is an argument
     * @return: full register variable
     * 
     * Casts half registers to full registers
     */
    protected Variable checkForParentRegister(Varnode node) {
        Variable var = new Variable();
        Register reg = context.getRegister(node);
        Register parent = reg.getBaseRegister();
        if(parent != null) {
            Varnode parent_node = context.getRegisterVarnode(parent);
            var.setName(parent.getName());
            var.setSize(parent_node.getSize());
        } else {
            var.setName(reg.getName());
            var.setSize(node.getSize());
        }
        var.setIsVirtual(false);

        return var;
    }


    /**
     * @param func: Ghidra function object
     * @return: new Sub Term
     * 
     * Creates a Sub Term with an unique TID consisting of the prefix sub and its entry address.
     */
    protected Term<Sub> createSubTerm(Function func) {
        return new Term<Sub>(functionEntryPoints.get(func.getEntryPoint().toString()), new Sub(func.getName(), func.getBody()));
    }


    /**
     * @param tidAddress: tid address for block
     * @param suffix: Tid suffix
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
     * 
     * @param intraJump: Indicator if jump occured inside pcode block
     * @return: new Jmp Term
     * 
     * Creates a Jmp Term with an unique TID consisting of the prefix jmp, its instruction address and the index of the pcode in the block.
     * Depending on the instruction, it either has a goto label, a goto label and a condition or a call object.
     */
    protected ArrayList<Term<Jmp>> createJmpTerm(Boolean intraJump) {
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
                jumps.add(new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.CALL, resolveCallMenmonic(call, mnemonic), call, PcodeBlockData.pcodeIndex)));
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
    protected ArrayList<Term<Jmp>> handleConditionalBranches(Tid conditionalTid, Boolean intraJump) {
        ArrayList<Term<Jmp>> branches = new ArrayList<Term<Jmp>>();
        String branchSiteAddress = new String(conditionalTid.getAddress());
        Tid branchTid = new Tid(String.format("instr_%s_%s", branchSiteAddress, PcodeBlockData.pcodeIndex + 1), branchSiteAddress);
        Tid targetTid = new Tid();

        if(intraJump) {
            targetTid = new Tid(String.format("blk_%s_%s", branchSiteAddress, PcodeBlockData.pcodeIndex + 2), branchSiteAddress);
        } else {
            targetTid = new Tid(String.format("blk_%s", PcodeBlockData.instruction.getFallThrough().toString()), PcodeBlockData.instruction.getFallThrough().toString());
        }

        branches.add(new Term<Jmp>(conditionalTid, new Jmp(ExecutionType.JmpType.GOTO, PcodeBlockData.pcodeOp.getMnemonic(), createLabel(null), createVariable(PcodeBlockData.pcodeOp.getInput(1)), PcodeBlockData.pcodeIndex)));
        branches.add(new Term<Jmp>(branchTid, new Jmp(ExecutionType.JmpType.GOTO, "BRANCH", new Label(targetTid), PcodeBlockData.pcodeIndex + 1)));

        return branches;
    }


    /**
     * 
     * @param call: indirect call
     * @param mnemonic: call mnemonic
     * @return: direkt call or indirekt call
     * 
     * Checks whether the indirect call could have been resolved and casts it into a direct call
     */
    protected String resolveCallMenmonic(Call call, String mnemonic) {
        if (mnemonic.equals("CALLIND") && call.getTarget().getIndirect() == null) {
            return "CALL";
        }

        return mnemonic;
    }


    /**
     * @return: new Def Term
     * 
     * Creates a Def Term with an unique TID consisting of the prefix def, its instruction address and the index of the pcode in the block.
     */
    protected Term<Def> createDefTerm() {
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
    protected Variable createVariable(Varnode node) {
        Variable var = new Variable();
        if (node.isRegister()) {
            var.setName(context.getRegister(node).getName());
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
     * @return: new Epxression
     * 
     * Create an Expression using the input varnodes of the pcode instruction.
     */
    protected Expression createExpression() {
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
    protected Label createLabel(Address fallThrough) {
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
    protected Label handleLabelsForCalls(PcodeOp pcodeOp) {
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
    protected Tid getTargetTid(PcodeOp pcodeOp) {
        // First check whether the parsed address from the pcodeOp operation
        // is in the entry points map and if so, return the corresponding Tid.
        // This is a cheap operation
        String targetAddress = parseCallTargetAddress(pcodeOp);
        if(functionEntryPoints.containsKey(targetAddress)) {
            return functionEntryPoints.get(targetAddress);
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
            if(functionEntryPoints.containsKey(flow.toString())) {
                return functionEntryPoints.get(flow.toString());
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
                return updateExternalSymbolLocations(flow, targetAddress);
            }
        }

        return null;
    }


    /**
     * 
     * @param flow: flow from instruction to target
     * @param targetAddress: address of target
     * 
     * Adds function pointer address to external symbol and updates the TID.
     */
    protected Tid updateExternalSymbolLocations(Address flow, String targetAddress) {
        Function external = funcMan.getFunctionAt(flow);
        ExternSymbol symbol = externalSymbolMap.get(external.getName());
        symbol.getAddresses().add(targetAddress);
        if(symbol.getTid().getId().startsWith("sub_EXTERNAL")) {
            Tid targetTid = new Tid(String.format("sub_%s", targetAddress), targetAddress);
            functionEntryPoints.put(targetAddress, targetTid);
            symbol.setTid(targetTid);
            return targetTid;
        }
        return symbol.getTid();
    }


    /**
     * 
     * @param op: call pcode operation
     * @return: Address of function pointer
     * 
     * Parses the function pointer address out of an call instruction
     */
    protected String parseCallTargetAddress(PcodeOp op) {
        if(op.getInput(0).isAddress()) {
            return op.getInput(0).getAddress().toString();
        }
        return null;
    }


    /**
     * 
     * @return: new Call
     * 
     * Creates a Call object, using a target and return Label.
     */
    protected Call createCall() {
        String callString = null;
        Call call;
        if(PcodeBlockData.pcodeOp.getOpcode() == PcodeOp.CALLOTHER) {
            callString = ghidraProgram.getLanguage().getUserDefinedOpName((int) PcodeBlockData.pcodeOp.getInput(0).getOffset());
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


    /**
     * @param address: Virtual register address
     * @return: Prefixed virtual register name
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
        Matcher matcher = Pattern.compile("^Stack\\[([a-zA-Z0-9]*)\\]$").matcher(param);
        if(matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }

    /**
     * Adds parameter register to the RegisterCallingConvention object
     */
    protected void addParameterRegister(HashMap<String, RegisterConvention> conventions) {
        PrototypeModel[] models = ghidraProgram.getCompilerSpec().getCallingConventions();
        for(PrototypeModel model : models) {
            String cconv = model.getName();
            if(conventions.get(cconv) != null) {
                ArrayList<String> parameters = conventions.get(cconv).getParameter();
                for(VariableStorage storage : model.getPotentialInputRegisterStorage(ghidraProgram)) {
                    parameters.add(storage.getRegister().getName());
                }
            }
        }
    }

}
