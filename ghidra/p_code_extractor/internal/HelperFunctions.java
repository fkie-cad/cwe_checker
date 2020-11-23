package internal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import bil.Variable;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.VarnodeContext;
import ghidra.util.task.TaskMonitor;
import term.*;

public final class HelperFunctions {
    // private constructor for non-instantiable classes

    public static VarnodeContext context;
    public static ghidra.program.model.listing.Program ghidraProgram;
    public static FunctionManager funcMan;
    public static HashMap<String, Tid> functionEntryPoints = new HashMap<String, Tid>();
    public static TaskMonitor monitor;

    private HelperFunctions() {
        throw new UnsupportedOperationException();
    }


    /**
     * 
     * @param op: call pcode operation
     * @return: Address of function pointer
     * 
     * Parses the function pointer address out of an call instruction
     */
    public static String parseCallTargetAddress(PcodeOp op) {
        if(op.getInput(0).isAddress()) {
            return op.getInput(0).getAddress().toString();
        }
        return null;
    }


    /**
     * @param address: Virtual register address
     * @return: Prefixed virtual register name
     * 
     * Prefixes virtual register with $U.
     */
    public static String renameVirtualRegister(String address) {
        return "$U" + address.replaceFirst("^(unique:0+(?!$))", "");
    }


    /**
     * @param node: Register Varnode
     * @return: Register mnemonic
     * 
     * Gets register mnemonic.
     */
    public static String getRegisterMnemonic(Varnode node) {
        return context.getRegister(node).getName();
    }


    /**
     * @param constant: Constant value
     * @return: Constant value without prefix
     * 
     * Removes the consts prefix from the constant.
     */
    public static String removeConstantPrefix(String constant) {
        return constant.replaceFirst("^(const:)", "");
    }


    /**
     * 
     * @param param: stack parameter
     * @return: stack parameter without stack prefix
     * 
     * Removes stack prefix from stack parameter. e.g. Stack[0x4] => 0x4
     */
    public static String removeStackPrefix(String param) {
        Matcher matcher = Pattern.compile("^Stack\\[([a-zA-Z0-9]*)\\]$").matcher(param);
        if(matcher.find()) {
            return matcher.group(1);
        }
        return "";
    }


    /**
     * 
     * @param call: indirect call
     * @param mnemonic: call mnemonic
     * @return: direkt call or indirekt call
     * 
     * Checks whether the indirect call could have been resolved and casts it into a direct call
     */
    public static String resolveCallMenmonic(Call call, String mnemonic) {
        if (mnemonic.equals("CALLIND") && call.getTarget().getIndirect() == null) {
            return "CALL";
        }

        return mnemonic;
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
    public static Variable checkForParentRegister(Varnode node) {
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


    public static Boolean hasVoidReturn(Function func) {
        return func.hasNoReturn() || func.getReturn().getDataType().getName().equals("void");
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
    public static Boolean notInReferences(Function func) {
        for(Function calling : func.getCallingFunctions(monitor)) {
            if(calling.getName().equals(func.getName())) {
                return false;
            }
        }

        return true;
    }


    /**
     * 
     * @param block: block term
     * @return: boolean whether block ends on definition
     * 
     * Checks whether the current block term ends on a definition
     */
    public static Boolean lastInstructionIsDef(Term<Blk> block) {
        ArrayList<Term<Jmp>> jumps = block.getTerm().getJmps();
        ArrayList<Term<Def>> defs = block.getTerm().getDefs();

        if(defs.size() > 0 && jumps.size() == 0) {
            return true;
        }
        return false;
    }


    /**
     * 
     * @param symTab: symbol table
     * @return: list of program entry points
     * 
     * Creates a list of program entry points to add to the program term
     */
    public static ArrayList<Tid> addEntryPoints(SymbolTable symTab) {
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
     * @return: CPU architecture as string.
     * 
     * Uses Ghidra's language id to extract the CPU arch as "arch-bits" e.g. x86_64, x86_32 etc.
     */
    public static String getCpuArchitecture() {
        String langId = ghidraProgram.getCompilerSpec().getLanguage().getLanguageID().getIdAsString();
        String[] arch = langId.split(":");
        return arch[0] + "_" + arch[2];
    }
}
