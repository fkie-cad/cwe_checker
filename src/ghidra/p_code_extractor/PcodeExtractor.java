import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.HashMap;
import java.util.LinkedList;
import java.io.FileWriter;
import java.io.IOException;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.util.VarnodeContext;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.util.VarnodeContext;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.InvalidInputException;
import com.google.gson.*;

public class PcodeExtractor extends GhidraScript {

    /**
     * Main routine for extracting pcode, register properties, CPU architecture
     * details, stack pointer, datatype properties,
     * image base and calling conventions.
     * All of the above are put together via a ProjectSimple object and this is JSON
     * serialized afterwards.
     * Most of the components are represented as "Simple" classes and only contain
     * the desired information.
     */
    @Override
    protected void run() throws Exception {
        TaskMonitor monitor = getMonitor();
        Program ghidraProgram = currentProgram;
        FunctionManager funcMan = ghidraProgram.getFunctionManager();
        VarnodeContext context = new VarnodeContext(ghidraProgram, ghidraProgram.getProgramContext(),
                ghidraProgram.getProgramContext());
        SimpleBlockModel simpleBM = new SimpleBlockModel(ghidraProgram);
        Listing listing = ghidraProgram.getListing();
        Language language = ghidraProgram.getLanguage();

        // collecting function's pcode
        ArrayList<FunctionSimple> functions = new ArrayList<FunctionSimple>();
        for (Function func : funcMan.getFunctions(true)) {
            FunctionSimple function = new FunctionSimple(func, context, simpleBM, monitor, listing);
            functions.add(function);
        }

        // collecting register properties
        ArrayList<RegisterProperties> registerProperties = new ArrayList<RegisterProperties>();
        for (Register reg : language.getRegisters()) {
            registerProperties.add(new RegisterProperties(reg, context));
        }

        // collecting architecture details, e.g. "x86:LE:64:default"
        String cpuArch = language.getLanguageID().getIdAsString();

        // collecting stack pointer
        CompilerSpec comSpec = ghidraProgram.getCompilerSpec();
        VarnodeSimple stackPointerRegister = new VarnodeSimple(comSpec.getStackPointer());

        // collecting datatype properties
        DatatypeProperties dataTypeProperties = new DatatypeProperties(ghidraProgram);

        // collecting image base offset
        String imageBase = "0x" + ghidraProgram.getImageBase().toString(false, true);

        // collecting calling conventions
        HashMap<String, CallingConventionSimple> callingConventions = new HashMap<String, CallingConventionSimple>();
        for (PrototypeModel prototypeModel : comSpec.getCallingConventions()) {
            CallingConventionSimple cconv = new CallingConventionSimple(prototypeModel.getName(),
                    prototypeModel.getUnaffectedList(),
                    prototypeModel.getKilledByCallList(),
                    context);
            ArrayList<VarnodeSimple> integer_register = get_integer_parameter_register(prototypeModel, ghidraProgram,
                    context);
            cconv.setIntegerParameterRegister(integer_register);

            ArrayList<VarnodeSimple> float_register = get_float_parameter_register(prototypeModel, ghidraProgram,
                    context);
            cconv.setFloatParameterRegister(float_register);

            VarnodeSimple integer_return_register = get_integer_return_register(prototypeModel, ghidraProgram,
                    context);
            cconv.setIntegerReturnRegister(integer_return_register);

            VarnodeSimple float_return_register = get_float_return_register(prototypeModel, ghidraProgram, context);
            cconv.setFloatReturnRegister(float_return_register);

            callingConventions.put(prototypeModel.getName(), cconv);
        }

        // assembling everything together
        ProjectSimple project = new ProjectSimple(functions, registerProperties, cpuArch, stackPointerRegister,
                callingConventions, dataTypeProperties, imageBase);

        // serialization

        Gson gson = new GsonBuilder().setPrettyPrinting().serializeNulls().create();
        try {
            FileWriter writer = new FileWriter(getScriptArgs()[0]);
            gson.toJson(project, writer);
            writer.close();
        } catch (JsonIOException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        println("Pcode was successfully extracted!");
    }

    /**
     * Returns list of VarnodeSimple of integer parameter in order defined by the
     * calling convention.
     * 
     * This functions returns the base register, e.g. RDI is returned and not EDI.
     * *Approximation*: This function returns the first 10 or less integer registers
     * This is due to the only way of extracting the integer parameter register
     * available
     * (https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/PrototypeModel.html)
     */
    private ArrayList<VarnodeSimple> get_integer_parameter_register(PrototypeModel prototypeModel,
            Program ghidraProgram, VarnodeContext context) {
        ArrayList<VarnodeSimple> integer_parameter_register = new ArrayList<VarnodeSimple>();

        // prepare a parameter list of integers only
        DataTypeManager dataTypeManager = ghidraProgram.getDataTypeManager();
        IntegerDataType[] integer_parameter_list = new IntegerDataType[10];
        for (int i = 0; i < integer_parameter_list.length; i++) {
            integer_parameter_list[i] = new IntegerDataType(dataTypeManager);
        }
        // get all possible parameter passing registers, including floating point
        // registers
        for (VariableStorage potential_register : prototypeModel.getPotentialInputRegisterStorage​​(ghidraProgram)) {
            // get all used registers by the prepared integer parameter list
            for (VariableStorage integer_register : prototypeModel.getStorageLocations​(ghidraProgram,
                    integer_parameter_list, false)) {
                // take only registers that are in common
                if (integer_register.isRegisterStorage()
                        && integer_register.getRegister().getParentRegister() == potential_register.getRegister()) {
                    integer_parameter_register.add(new VarnodeSimple(potential_register.getFirstVarnode(), context));
                }
            }
        }
        return integer_parameter_register;
    }

    /**
     * Returns list of VarnodeSimple of float parameter in order defined by the
     * calling convention.
     * 
     * This functions returns the *not* register, e.g. XMM0_Qa is *not* changed to
     * YMM0.
     * *Approximation*: This function returns the first 10 or less float registers
     * This is due to the only way of extracting the float parameter register
     * available
     * (https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/PrototypeModel.html)
     */
    private ArrayList<VarnodeSimple> get_float_parameter_register(PrototypeModel prototypeModel, Program ghidraProgram,
            VarnodeContext context) {
        ArrayList<VarnodeSimple> float_parameter_register = new ArrayList<VarnodeSimple>();

        // get all possible parameter passing registers, including integer registers
        List<VariableStorage> potential_register = new LinkedList<>(
                Arrays.asList(prototypeModel.getPotentialInputRegisterStorage​​(ghidraProgram)));
        potential_register.removeIf(reg -> reg.getRegister() == null);

        // remove all integer parameter register
        for (VarnodeSimple integer_register : get_integer_parameter_register(prototypeModel, ghidraProgram, context)) {
            potential_register.removeIf(reg -> reg.getRegister().getName() == integer_register.getId());
        }

        for (VariableStorage float_register : potential_register) {
            float_parameter_register.add(new VarnodeSimple(float_register.getFirstVarnode(), context));
        }

        return float_parameter_register;
    }

    /**
     * Returns the calling convention's first integer return register.
     * 
     * *Limitation*: By definition, the first element of
     * `PrototypeModel.getStorageLocations()` describes the
     * return register. Composed registers are not supported.
     * (https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/PrototypeModel.html)
     */
    public VarnodeSimple get_integer_return_register(PrototypeModel prototypeModel, Program ghidraProgram,
            VarnodeContext context) {
        // prepare a list of one integer parameters only
        DataTypeManager dataTypeManager = ghidraProgram.getDataTypeManager();
        PointerDataType[] pointer_parameter_list = { new PointerDataType(dataTypeManager) };
        // first element of `getStorageLocations()` describes the return location
        VariableStorage pointer_return_register = prototypeModel.getStorageLocations​(ghidraProgram,
                pointer_parameter_list, false)[0];

        return new VarnodeSimple(pointer_return_register.getFirstVarnode(), context);
    }

    /**
     * Returns the calling convention's first float return register.
     * 
     * *Approximation*: This function uses the double datatype to query the return
     * register. The returned register
     * is choosen according to the datatype size, thus sub-registers of the actual
     * return register might be returned.
     * *Limitation*: By definition, the first element of
     * `PrototypeModel.getStorageLocations()` describes the
     * return register. Composed registers are not supported.
     * For x86_64 this can be considered a bug, since XMM0 and XMM1 (YMM0) can be
     * such a composed retrun register.
     * This property is not modeled in
     * Ghidra/Processors/x86/data/languages/x86_64-*.cspec.
     */
    public VarnodeSimple get_float_return_register(PrototypeModel prototypeModel, Program ghidraProgram,
            VarnodeContext context) {
        // prepare a list of one double parameters only
        DataTypeManager dataTypeManager = ghidraProgram.getDataTypeManager();
        DoubleDataType[] double_parameter_list = { new DoubleDataType(dataTypeManager) };
        // first element of `getStorageLocations()` describes the return location
        VariableStorage double_return_register = prototypeModel.getStorageLocations​(ghidraProgram,
                double_parameter_list, false)[0];
        VarnodeSimple double_return_Varnode_simple = new VarnodeSimple(double_return_register.getFirstVarnode(),
                context);
        if (double_return_Varnode_simple.toString()
                .equals(get_integer_return_register(prototypeModel, ghidraProgram, context).toString())) {
            return null;
        }

        return new VarnodeSimple(double_return_register.getFirstVarnode(), context);
    }

}