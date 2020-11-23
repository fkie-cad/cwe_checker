package symbol;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import bil.Expression;
import bil.Variable;
import internal.HelperFunctions;
import internal.TermCreator;
import term.Arg;
import term.Tid;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SymbolTable;


public class ExternSymbolCreator {

    public static HashMap<String, ExternSymbol> externalSymbolMap = new HashMap<String, ExternSymbol>();

    // private constructor for non-instantiable classes
    private ExternSymbolCreator() {
        throw new UnsupportedOperationException();
    }

    /**
     * 
     * @param symTab: symbol table
     * 
     * Creates a map of external symbols to add to the program term
     */
    public static void createExternalSymbolMap(SymbolTable symTab) {
        HashMap<String, ArrayList<Function>> symbolMap = new HashMap<String, ArrayList<Function>>();
        HelperFunctions.funcMan.getExternalFunctions().forEach(func -> {
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
    public static void getThunkFunctions(Function func, ArrayList<Function> thunkFuncs) {
        Address[] thunks = func.getFunctionThunkAddresses();
        if(thunks != null) {
            for(Address thunkAddr : thunks) {
                Function thunkFunction = HelperFunctions.funcMan.getFunctionAt(thunkAddr);
                thunkFuncs.add(thunkFunction);
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
    public static void addToSymbolMap(HashMap<String, ArrayList<Function>> symbolMap, Function func) {
        if(symbolMap.containsKey(func.getName())) {
            symbolMap.get(func.getName()).add(func);
        } else {
            symbolMap.put(func.getName(), new ArrayList<Function>(){{add(func);}});
        }
    }


    /**
     * @param symbolMap: External symbol map
     * 
     * Creates external symbol map with an unique TID, a calling convention and argument objects.
     */
    public static void createExternalSymbols(HashMap<String, ArrayList<Function>> symbolMap) {
        for(Map.Entry<String, ArrayList<Function>> functions : symbolMap.entrySet()) {
            ExternSymbol extSym = new ExternSymbol();
            extSym.setName(functions.getKey());
            for(Function func : functions.getValue()) {
                if(HelperFunctions.notInReferences(func)) {
                    extSym.setTid(new Tid(String.format("sub_%s", func.getEntryPoint().toString()), func.getEntryPoint().toString()));
                    extSym.setNoReturn(func.hasNoReturn());
                    extSym.setArguments(createArguments(func));
                    extSym.setCallingConvention(HelperFunctions.funcMan.getDefaultCallingConvention().toString());
                }
                if(!func.isExternal()) {
                    extSym.getAddresses().add(func.getEntryPoint().toString());
                }
            }
            externalSymbolMap.put(functions.getKey(), extSym);
        }

    }


    /**
     * 
     * @param flow: flow from instruction to target
     * @param targetAddress: address of target
     * @param funcMan: function manager
     * 
     * Adds function pointer address to external symbol and updates the TID.
     */
    public static Tid updateExternalSymbolLocations(Address flow, String targetAddress, FunctionManager funcMan) {
        Function external = funcMan.getFunctionAt(flow);
        ExternSymbol symbol = externalSymbolMap.get(external.getName());
        symbol.getAddresses().add(targetAddress);
        if(symbol.getTid().getId().startsWith("sub_EXTERNAL")) {
            Tid targetTid = new Tid(String.format("sub_%s", targetAddress), targetAddress);
            HelperFunctions.functionEntryPoints.put(targetAddress, targetTid);
            symbol.setTid(targetTid);
            return targetTid;
        }
        return symbol.getTid();
    }

    /**
     * @param param: Function parameter
     * @return: new Arg
     * 
     * Specifies if the argument is a stack variable or a register.
     */
    public static Arg specifyArg(Parameter param) {
        Arg arg = new Arg();
        if (param.isStackVariable()) {
            Variable stackVar = TermCreator.createVariable(param.getFirstStorageVarnode());
            arg.setLocation(new Expression("LOAD", stackVar));
        } else if (param.isRegisterVariable()) {
            arg.setVar(HelperFunctions.checkForParentRegister(param.getFirstStorageVarnode()));
        }
        arg.setIntent("INPUT");

        return arg;
    }


    /**
     * @param func: function to get arguments
     * @return: new Arg ArrayList
     * 
     * Creates Arguments for the ExternSymbol object.
     */
    public static ArrayList<Arg> createArguments(Function func) {
        ArrayList<Arg> args = new ArrayList<Arg>();
        Parameter[] params = func.getParameters();
        for (Parameter param : params) {
            args.add(specifyArg(param));
        }
        if (!HelperFunctions.hasVoidReturn(func)) {
            for(Varnode node : func.getReturn().getVariableStorage().getVarnodes()) {
                args.add(new Arg(HelperFunctions.checkForParentRegister(node), "OUTPUT"));
            }
        }

        return args;
    }
}
