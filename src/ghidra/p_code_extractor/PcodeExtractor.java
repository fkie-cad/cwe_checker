import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.HashMap;
import java.util.LinkedList;
import java.io.FileWriter;
import java.io.IOException;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.lang.Language;
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
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.InvalidInputException;
import com.google.gson.*;

public class PcodeExtractor extends GhidraScript {

	/**
	 * Main routine for extracting pcode, register properties, CPU architecture
	 * details, stack pointer, datatype properties,
	 * image base and calling conventions.
	 * All of the above are put together via a PcodeProject object and this is JSON
	 * serialized afterwards.
	 * Most of the components are represented as "Simple" classes and only contain
	 * the desired information.
	 */
	@Override
	protected void run() throws Exception {
		TaskMonitor monitor = getMonitor();
		ghidra.program.model.listing.Program ghidraProgram = currentProgram;
		FunctionManager funcMan = ghidraProgram.getFunctionManager();
		VarnodeContext context = new VarnodeContext(ghidraProgram, ghidraProgram.getProgramContext(),
		    ghidraProgram.getProgramContext());
		SimpleBlockModel simpleBM = new SimpleBlockModel(ghidraProgram);
		Listing listing = ghidraProgram.getListing();
		Language language = ghidraProgram.getLanguage();

		// collect datatype properties
		DatatypeProperties dataTypeProperties = new DatatypeProperties(ghidraProgram);

		// collect external functions
		HashMap<String, ExternFunction> externalFunctions = new HashMap<String, ExternFunction>();
		for (ghidra.program.model.listing.Function ext_func : funcMan.getExternalFunctions()) {

			ArrayList<Varnode> parameters = new ArrayList<Varnode>();
			for (Parameter parameter : ext_func.getParameters()) {
				parameters.add(new Varnode(parameter.getFirstStorageVarnode(), context, dataTypeProperties));

			}
			Varnode return_location = null;
			if (ext_func.getReturn().getFirstStorageVarnode() != null) {
				return_location = new Varnode(ext_func.getReturn().getFirstStorageVarnode(), context, dataTypeProperties);
			}

			// Note: We work under the assumption that external functions
			// can be distinguised by name. If this ever turns out to be
			// problematic we must start mangling it with additional
			// information.
			if (externalFunctions.containsKey(ext_func.getName())) {
				throw new Exception("Duplicate external symbol name.");
			}

			externalFunctions.put(ext_func.getName(),
			                      (new ExternFunction(ext_func.getName(), funcMan.getDefaultCallingConvention().toString(),
			                              parameters, return_location, ext_func.hasNoReturn(), ext_func.hasVarArgs())));
		}

		// collect function's pcode
		ArrayList<Function> functions = new ArrayList<Function>();
		for (ghidra.program.model.listing.Function func : funcMan.getFunctions(true)) {
			// If a function is thunk for an external function, add the address
			// to the external function.
			//
			// Note: We add the thunk function to the internal functions anyways.
			if (func.isThunk()) {
				ghidra.program.model.listing.Function thunked_func = func.getThunkedFunction(true);
				if (thunked_func.isExternal()) {
					if (externalFunctions.containsKey(thunked_func.getName())) {
						externalFunctions.get(thunked_func.getName()).add_thunk_function_address(func.getEntryPoint());
					}
				}
			}

			Function function = new Function(func, context, simpleBM, monitor, listing, dataTypeProperties);
			functions.add(function);
		}

		// collect entry points to the binary
		ArrayList<String> entry_points = new ArrayList<String>();
		for (Address address : (currentProgram.getSymbolTable().getExternalEntryPointIterator())) {
			entry_points.add("0x" + address.toString(false, false));
		}

		// collect register properties
		ArrayList<RegisterProperties> registerProperties = new ArrayList<RegisterProperties>();
		for (Register reg : language.getRegisters()) {
			registerProperties.add(new RegisterProperties(reg, context));
		}

		// collect architecture details, e.g. "x86:LE:64:default"
		String cpuArch = language.getLanguageID().getIdAsString();

		// collect stack pointer
		CompilerSpec comSpec = ghidraProgram.getCompilerSpec();
		Varnode stackPointerRegister = new Varnode(comSpec.getStackPointer());

		// collect image base offset
		String imageBase = "0x" + ghidraProgram.getImageBase().toString(false, false);

		// collect calling conventions
		HashMap<String, CallingConvention> callingConventions = new HashMap<String, CallingConvention>();
		for (PrototypeModel prototypeModel : comSpec.getCallingConventions()) {
			CallingConvention cconv = new CallingConvention(prototypeModel.getName(),
			    prototypeModel.getUnaffectedList(),
			    prototypeModel.getKilledByCallList(),
			    context, dataTypeProperties);
			ArrayList<Varnode> integer_register = get_integer_parameter_register(prototypeModel, ghidraProgram,
			                                      context);
			cconv.setIntegerParameterRegister(integer_register);

			ArrayList<Varnode> float_register = get_float_parameter_register(prototypeModel, ghidraProgram,
			                                    context);
			cconv.setFloatParameterRegister(float_register);

			Varnode integer_return_register = get_integer_return_register(prototypeModel, ghidraProgram,
			                                  context);
			cconv.setIntegerReturnRegister(integer_return_register);

			Varnode float_return_register = get_float_return_register(prototypeModel, ghidraProgram, context);
			cconv.setFloatReturnRegister(float_return_register);

			callingConventions.put(prototypeModel.getName(), cconv);
		}

		// assembling everything together
		PcodeProject project = new PcodeProject(functions, registerProperties, cpuArch, externalFunctions,
		                                        entry_points, stackPointerRegister, callingConventions, dataTypeProperties, imageBase);

		// serialization
		Gson gson = new GsonBuilder().setPrettyPrinting().serializeNulls().create();
		FileWriter writer = null;
		String jsonPath = getScriptArgs()[0];

		try {
			writer = new FileWriter(jsonPath);
		} catch (IOException e) {
			System.out.printf("%s is a directory, could not be created or can not be opened", getScriptArgs()[0]);
			e.printStackTrace();
			System.exit(1);
		}
		try {
			gson.toJson(project, writer);
			writer.flush();
			writer.close();
		} catch (Exception e) {
			System.out.printf("Could not write to %s", getScriptArgs()[0]);
			e.printStackTrace();
			System.exit(1);
		}

		println("Pcode was successfully extracted!");

	}

	/**
	 * Returns list of Varnode of integer parameter in order defined by the
	 * calling convention.
	 *
	 * This functions returns the base register, e.g. RDI is returned and not EDI.
	 * *Approximation*: This function returns the first 10 or less integer registers
	 * This is due to the only way of extracting the integer parameter register
	 * available
	 * (https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/PrototypeModel.html)
	 */
	private ArrayList<Varnode> get_integer_parameter_register(PrototypeModel prototypeModel,
	        ghidra.program.model.listing.Program ghidraProgram, VarnodeContext context) {
		ArrayList<Varnode> integer_parameter_register = new ArrayList<Varnode>();
		DatatypeProperties dataTypeProperties = new DatatypeProperties(ghidraProgram);

		for (Register base_register : get_integer_parameter_base_register(prototypeModel, ghidraProgram)) {
			integer_parameter_register.add(new Varnode(context.getRegisterVarnode(base_register), context, dataTypeProperties));
		}
		return integer_parameter_register;
	}

	/**
	 * Returns the base registers of the integer parameter registers in order
	 * defined by the calling convention.
	 */
	private ArrayList<Register> get_integer_parameter_base_register(PrototypeModel prototypeModel,
	        ghidra.program.model.listing.Program ghidraProgram) {
		ArrayList<Register> integer_parameter_register = new ArrayList<Register>();

		// prepare a parameter list of integers only
		DataTypeManager dataTypeManager = ghidraProgram.getDataTypeManager();
		IntegerDataType[] integer_parameter_list = new IntegerDataType[10];
		for (int i = 0; i < integer_parameter_list.length; i++) {
			integer_parameter_list[i] = new IntegerDataType(dataTypeManager);
		}
		// get all used registers by the prepared integer parameter list
		// (the first element always describes the return value storage and is skipped)
		VariableStorage[] storage_locations = prototypeModel.getStorageLocations(ghidraProgram,
		        integer_parameter_list, false);
		List<VariableStorage> integer_parameter_storage = Arrays.asList(storage_locations).subList(1,
		        storage_locations.length);
		// get all possible parameter passing registers, including floating point
		// registers
		for (VariableStorage potential_register : prototypeModel.getPotentialInputRegisterStorage(ghidraProgram)) {
			if (!potential_register.isRegisterStorage()) {
				continue;
			}
			Register base_register = potential_register.getRegister().getBaseRegister();
			for (VariableStorage integer_register : integer_parameter_storage) {
				// take only registers that are in common
				// (compare base registers, since e.g. ARM's r0 has no parent register
				// and PowerPC's 32-bit parameter registers are subregisters of 64-bit registers)
				if (integer_register.isRegisterStorage()
				        && integer_register.getRegister().getBaseRegister() == base_register
				        && !integer_parameter_register.contains(base_register)) {
					integer_parameter_register.add(base_register);
				}
			}
		}
		return integer_parameter_register;
	}

	/**
	 * Returns list of Varnode of float parameter in order defined by the
	 * calling convention.
	 *
	 * This functions returns the *not* register, e.g. XMM0_Qa is *not* changed to
	 * YMM0.
	 * *Approximation*: This function returns the first 10 or less float registers
	 * This is due to the only way of extracting the float parameter register
	 * available
	 * (https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/PrototypeModel.html)
	 */
	private ArrayList<Varnode> get_float_parameter_register(PrototypeModel prototypeModel, ghidra.program.model.listing.Program ghidraProgram,
	        VarnodeContext context) {
		ArrayList<Varnode> float_parameter_register = new ArrayList<Varnode>();
		DatatypeProperties dataTypeProperties = new DatatypeProperties(ghidraProgram);

		// get all possible parameter passing registers, including integer registers
		List<VariableStorage> potential_register = new LinkedList<>(
		    Arrays.asList(prototypeModel.getPotentialInputRegisterStorage(ghidraProgram)));
		potential_register.removeIf(reg -> reg.getRegister() == null);

		// remove all integer parameter register
		ArrayList<Register> integer_register = get_integer_parameter_base_register(prototypeModel, ghidraProgram);
		potential_register.removeIf(reg -> integer_register.contains(reg.getRegister().getBaseRegister()));

		for (VariableStorage float_register : potential_register) {
			float_parameter_register.add(new Varnode(float_register.getFirstVarnode(), context, dataTypeProperties));
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
	public Varnode get_integer_return_register(PrototypeModel prototypeModel, ghidra.program.model.listing.Program ghidraProgram,
	        VarnodeContext context) {
		DatatypeProperties dataTypeProperties = new DatatypeProperties(ghidraProgram);
		// prepare a list of one integer parameters only
		DataTypeManager dataTypeManager = ghidraProgram.getDataTypeManager();
		PointerDataType[] pointer_parameter_list = { new PointerDataType(dataTypeManager) };
		// first element of `getStorageLocations()` describes the return location
		VariableStorage pointer_return_register = prototypeModel.getStorageLocations(ghidraProgram,
		    pointer_parameter_list, false)[0];

		return new Varnode(pointer_return_register.getFirstVarnode(), context, dataTypeProperties);
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
	public Varnode get_float_return_register(PrototypeModel prototypeModel, ghidra.program.model.listing.Program ghidraProgram,
	        VarnodeContext context) {
		DatatypeProperties dataTypeProperties = new DatatypeProperties(ghidraProgram);
		// prepare a list of one double parameters only
		DataTypeManager dataTypeManager = ghidraProgram.getDataTypeManager();
		DoubleDataType[] double_parameter_list = { new DoubleDataType(dataTypeManager) };
		// first element of `getStorageLocations()` describes the return location
		VariableStorage double_return_register = prototypeModel.getStorageLocations(ghidraProgram,
		    double_parameter_list, false)[0];
		Varnode double_return_Varnode_simple = new Varnode(double_return_register.getFirstVarnode(),
		    context, dataTypeProperties);
		if (double_return_Varnode_simple.toString()
		        .equals(get_integer_return_register(prototypeModel, ghidraProgram, context).toString())) {
			return null;
		}

		return new Varnode(double_return_register.getFirstVarnode(), context, dataTypeProperties);
	}

}
