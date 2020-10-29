import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.HashMap;
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

        program = createProgramTerm();
        Project project = createProject();
        program = iterateFunctions(simpleBM, listing);

        String jsonPath = getScriptArgs()[0];
        Serializer ser = new Serializer(project, jsonPath);
        ser.serializeProject();
        TimeUnit.SECONDS.sleep(3);

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
                addJumpToCurrentBlock(lastBlockTerm.getTerm(), instrAddress, destinationAddress, null);
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
     */
    protected void analysePcodeBlockOfAssemblyInstruction() {
        PcodeBlockData.ops = PcodeBlockData.instruction.getPcode(true);
        if(PcodeBlockData.ops.length == 0 && !PcodeBlockData.instruction.isInDelaySlot()) {
            addJumpToCurrentBlock(PcodeBlockData.blocks.get(PcodeBlockData.blocks.size()-1).getTerm(), PcodeBlockData.instruction.getAddress().toString(), PcodeBlockData.instruction.getFallThrough().toString(), null);
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
        for(int pcodeIndex = 0; pcodeIndex < numberOfPcodeOps; pcodeIndex++) {
            PcodeOp pcodeOp = PcodeBlockData.ops[pcodeIndex];
            String mnemonic = pcodeOp.getMnemonic();
            if (this.jumps.contains(mnemonic)) {
                intraInstructionJumpOccured = processJump(pcodeOp, mnemonic, numberOfPcodeOps, pcodeIndex, intraInstructionJumpOccured);
            } else {
                PcodeBlockData.temporaryDefStorage.add(createDefTerm(pcodeIndex, pcodeOp));
            }
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
        addJumpToCurrentBlock(lastBlock.getTerm(), PcodeBlockData.instruction.getAddress().toString(), PcodeBlockData.instruction.getFallThrough().toString(), null);
        PcodeBlockData.blocks.add(createBlkTerm(PcodeBlockData.instruction.getFallThrough().toString(), null));
        PcodeBlockData.temporaryDefStorage.clear();
    }


    /**
     *
     * @param pcodeOp: pcode instruction
     * @param mnemonic: pcode mnemonic
     * @param numberOfPcodeOps: number of pcode instruction in pcode block
     * @param pcodeIndex: index of current pcode instruction
     * @param intraInstructionJumpOccured: indicator whether a jump occured inside a pcode block
     * @return: indicator whether a jump occured inside a pcode block
     * 
     * Processes jump pcode instruction by checking where it occurs.
     * Distinguishes between jumps inside a pcode block and jumps at the end of a pcode block
     */
    protected Boolean processJump(PcodeOp pcodeOp, String mnemonic, int numberOfPcodeOps, int pcodeIndex, Boolean intraInstructionJumpOccured) {

        int currentBlockCount = PcodeBlockData.blocks.size();
        Term<Blk> currentBlock = PcodeBlockData.blocks.get(currentBlockCount - 1);

        if(pcodeIndex < numberOfPcodeOps - 1) {
            intraInstructionJumpOccured = processJumpInPcodeBlock(pcodeOp, mnemonic, numberOfPcodeOps, pcodeIndex, intraInstructionJumpOccured, currentBlock);
            PcodeBlockData.temporaryDefStorage.clear();
        } else {
            intraInstructionJumpOccured = processJumpAtEndOfPcodeBlocks(pcodeOp, mnemonic, numberOfPcodeOps, pcodeIndex, intraInstructionJumpOccured, currentBlock);
        }

        return intraInstructionJumpOccured;
    }


    /**
     * 
     * @param pcodeOp: pcode instruction
     * @param mnemonic: pcode mnemonic
     * @param numberOfPcodeOps: number of pcode instruction in pcode block
     * @param pcodeIndex: index of current pcode instruction
     * @param intraInstructionJumpOccured: indicator whether a jump occured inside a pcode block
     * @param currentBlock: current block term
     * @return: indicator whether a jump occured inside a pcode block
     * 
     * Process jumps at the end of pcode blocks
     * If it is a return block, the call return address is changed to the current block
     */
    protected Boolean processJumpAtEndOfPcodeBlocks(PcodeOp pcodeOp, String mnemonic, int numberOfPcodeOps, int pcodeIndex, Boolean intraInstructionJumpOccured, Term<Blk> currentBlock) {
        intraInstructionJumpOccured = false;
        // Case 2: jump at the end of pcode group but not end of ghidra generated block.
        if(PcodeBlockData.instructionIndex < PcodeBlockData.numberOfInstructionsInBlock - 1 && PcodeBlockData.instruction.getDelaySlotDepth() == 0) {
            PcodeBlockData.blocks.add(createBlkTerm(PcodeBlockData.instruction.getFallThrough().toString(), null));
        }
        // Case 3: jmp at last pcode op at last instruction in ghidra generated block
        // If Case 2 is true, the 'currentBlk' will be the second to last block as the new block is for the next instruction
        if(pcodeOp.getOpcode() == PcodeOp.RETURN && currentBlock.getTid().getId().endsWith("_r")) {
            redirectCallReturn(currentBlock, pcodeOp);
            return intraInstructionJumpOccured;
        }
        currentBlock.getTerm().addMultipleDefs(PcodeBlockData.temporaryDefStorage);
        currentBlock.getTerm().addJmp(createJmpTerm(pcodeIndex, pcodeOp, mnemonic));
        PcodeBlockData.temporaryDefStorage.clear();

        return intraInstructionJumpOccured;
    }


    /**
     * 
     * @param pcodeOp: pcode instruction
     * @param mnemonic: pcode mnemonic
     * @param numberOfPcodeOps: number of pcode instruction in pcode block
     * @param pcodeIndex: index of current pcode instruction
     * @param intraInstructionJumpOccured: indicator whether a jump occured inside a pcode block
     * @param currentBlock: current block term
     * @return: indicator whether a jump occured inside a pcode block
     * 
     * Processes a jump inside a pcode block and distinguishes between intra jumps and call return pairs.
     */
    protected Boolean processJumpInPcodeBlock(PcodeOp pcodeOp, String mnemonic, int numberOfPcodeOps, int pcodeIndex, Boolean intraInstructionJumpOccured, Term<Blk> currentBlock) {
        if(!isCall(pcodeOp)) {
            intraInstructionJumpOccured = true;
            handleIntraInstructionJump(currentBlock.getTerm(), pcodeOp, pcodeIndex);
        } else {
            handleCallReturnPair(currentBlock, pcodeOp, pcodeIndex);
        }

        return intraInstructionJumpOccured;
    }


    /**
     * 
     * @param currentBlock: current block term
     * @param pcodeOp: pcode instruction
     * @param pcodeIndex: index of current pcode instruction
     * 
     * Adds an artificial jump to the previous block if an intra jump occurs and creates a new block.
     */
    protected void handleIntraInstructionJump(Blk currentBlock, PcodeOp pcodeOp, int pcodeIndex) {
        if(PcodeBlockData.instructionIndex > 0 && !(currentBlock.getDefs().size() == 0 && currentBlock.getJmps().size() == 0)) {
            jumpFromPreviousInstructionToNewBlock(currentBlock, pcodeOp, pcodeIndex);
        } else {
            currentBlock.addMultipleDefs(PcodeBlockData.temporaryDefStorage);
            currentBlock.addJmp(createJmpTerm(pcodeIndex, pcodeOp, pcodeOp.getMnemonic()));
        }
        PcodeBlockData.blocks.add(createBlkTerm(PcodeBlockData.instruction.getAddress().toString(), String.valueOf(pcodeIndex + 1)));
        
    }


    /**
     * 
     * @param currentBlock: current block term
     * @param pcodeOp: pcode instruction
     * @param pcodeIndex: index of current pcode instruction
     * 
     * Adds a jump from the previous instruction to a new intra block
     */
    protected void jumpFromPreviousInstructionToNewBlock(Blk currentBlock, PcodeOp pcodeOp, int pcodeIndex) {
        addJumpToCurrentBlock(currentBlock, PcodeBlockData.instruction.getFallFrom().toString(), PcodeBlockData.instruction.getAddress().toString(), null);
        createNewBlockForIntraInstructionJump(pcodeIndex, pcodeOp);
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
     * @param pcodeIndex: index of current pcode instruction
     * @param pcodeOp: pcode instruction
     * 
     * Creates a new block for the pcode instructions of the current assembly instruction and the intra jump
     */
    protected void createNewBlockForIntraInstructionJump(int pcodeIndex, PcodeOp pcodeOp){
        int nextBlockStartIndex;
        Term<Blk> newBlock;
        // If an assembly instruction's pcode block is split into multiple blocks, the blocks' TIDs have to be distinguished by pcode index as they share the same instruction address
        if(PcodeBlockData.temporaryDefStorage.size() > 0) {
            nextBlockStartIndex = PcodeBlockData.temporaryDefStorage.get(0).getTerm().getPcodeIndex();
            if(nextBlockStartIndex > 0) {
                newBlock = createBlkTerm(PcodeBlockData.instruction.getAddress().toString(), String.valueOf(nextBlockStartIndex));
            } else {
                newBlock = createBlkTerm(PcodeBlockData.instruction.getAddress().toString(), null);
            }
        } else {
            newBlock = createBlkTerm(PcodeBlockData.instruction.getAddress().toString(), null);
        }
        newBlock.getTerm().addMultipleDefs(PcodeBlockData.temporaryDefStorage);
        newBlock.getTerm().addJmp(createJmpTerm(pcodeIndex, pcodeOp, pcodeOp.getMnemonic()));
        PcodeBlockData.blocks.add(newBlock);
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
     * @param currentBlock: current block term
     * @param pcodeOp: pcode instruction
     * @param pcodeIndex: index of current pcode instruction
     * 
     * Handles call return pairs by creating a return block and redirecting the call's return to the return block
     */
    protected void handleCallReturnPair(Term<Blk> currentBlock, PcodeOp pcodeOp, int pcodeIndex) {
        currentBlock.getTerm().addMultipleDefs(PcodeBlockData.temporaryDefStorage);
        Term<Jmp> jump = createJmpTerm(pcodeIndex, pcodeOp, pcodeOp.getMnemonic());
        Term<Blk> returnBlock = createBlkTerm(PcodeBlockData.instruction.getAddress().toString(), "r");
        jump.getTerm().getCall().setReturn_(new Label(new Tid(returnBlock.getTid().getId(), returnBlock.getTid().getAddress())));
        currentBlock.getTerm().addJmp(jump);
        PcodeBlockData.blocks.add(returnBlock);
    }


    /**
     * 
     * @param currentBlock: current block term
     * @param pcodeOp: pcode instruction
     * 
     * Redirects the call's return address to the artificially created return block
     */
    protected void redirectCallReturn(Term<Blk> currentBlock, PcodeOp pcodeOp) {
        Tid jmpTid = new Tid(String.format("instr_%s_%s_r", PcodeBlockData.instruction.getAddress().toString(), 0), PcodeBlockData.instruction.getAddress().toString());
        Term<Jmp> ret = new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.RETURN, pcodeOp.getMnemonic(), createLabel(pcodeOp.getMnemonic(), pcodeOp, null), 0));
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
        Tid subTid = new Tid(String.format("sub_%s", func.getEntryPoint().toString()), func.getEntryPoint().toString());
        return new Term<Sub>(subTid, new Sub(func.getName(), func.getBody()));
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
     * @param pCodeCount: Pcode index in current block
     * @param pcodeOp:    Pcode instruction
     * @param mnemonic:   Pcode instruction mnemonic
     * @return: new Jmp Term
     * 
     * Creates a Jmp Term with an unique TID consisting of the prefix jmp, its instruction address and the index of the pcode in the block.
     * Depending on the instruction, it either has a goto label, a goto label and a condition or a call object.
     */
    protected Term<Jmp> createJmpTerm(int pCodeCount, PcodeOp pcodeOp, String mnemonic) {
        Address instrAddr = PcodeBlockData.instruction.getAddress();
        Tid jmpTid = new Tid(String.format("instr_%s_%s", instrAddr.toString(), pCodeCount), instrAddr.toString());
        if (mnemonic.equals("CBRANCH")) {
            return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, mnemonic, createLabel(mnemonic, pcodeOp, null), createVariable(pcodeOp.getInput(1)), pCodeCount));
        } else if (mnemonic.equals("BRANCH") || mnemonic.equals("BRANCHIND")) {
            return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.GOTO, mnemonic, createLabel(mnemonic, pcodeOp, null), pCodeCount));
        } else if (mnemonic.equals("RETURN")) {
            return new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.RETURN, mnemonic, createLabel(mnemonic, pcodeOp, null), pCodeCount));
        }

        Term<Jmp> call = new Term<Jmp>(jmpTid, new Jmp(ExecutionType.JmpType.CALL, mnemonic, createCall(mnemonic, pcodeOp), pCodeCount));
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
     * @return: new Def Term
     * 
     * Creates a Def Term with an unique TID consisting of the prefix def, its instruction address and the index of the pcode in the block.
     */
    protected Term<Def> createDefTerm(int pcodeIndex, PcodeOp pcodeOp) {
        Address instrAddr = PcodeBlockData.instruction.getAddress();
        Tid defTid = new Tid(String.format("instr_%s_%s", instrAddr.toString(), pcodeIndex), instrAddr.toString());
        if (pcodeOp.getMnemonic().equals("STORE")) {
            return new Term<Def>(defTid, new Def(createExpression(pcodeOp), pcodeIndex));
            // cast copy instructions that have address outputs into store instructions
        }
        return new Term<Def>(defTid, new Def(createVariable(pcodeOp.getOutput()), createExpression(pcodeOp), pcodeIndex));
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
     * @param pcodeOp: Pcode instruction
     * @return: new Epxression
     * 
     * Create an Expression using the input varnodes of the pcode instruction.
     */
    protected Expression createExpression(PcodeOp pcodeOp) {
        String mnemonic = pcodeOp.getMnemonic();
        List<Variable> in = new ArrayList<Variable>();

        for (Varnode input : pcodeOp.getInputs()) {
            in.add(createVariable(input));
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
                    jumpLabel = new Label((Variable) createVariable(pcodeOp.getInput(0)));
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
        return new Label((Variable) createVariable(pcodeOp.getInput(0)));
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
     * 
     * @param mnemonic: Pcode instruction mnemonic
     * @param pcodeOp:  Pcode instruction
     * @return: new Call
     * 
     * Creates a Call object, using a target and return Label.
     */
    protected Call createCall(String mnemonic, PcodeOp pcodeOp) {
        if(mnemonic.equals("CALLOTHER")) {
            String callString = ghidraProgram.getLanguage().getUserDefinedOpName((int) pcodeOp.getInput(0).getOffset());
            return new Call(createLabel(mnemonic, pcodeOp, null), createLabel(mnemonic, pcodeOp, PcodeBlockData.instruction.getFallThrough()), callString);
        }
        return new Call(createLabel(mnemonic, pcodeOp, null), createLabel(mnemonic, pcodeOp, PcodeBlockData.instruction.getFallThrough()));
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
        Matcher matcher = Pattern.compile("^Stack\\[(0x\\d)\\]$").matcher(param);
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
