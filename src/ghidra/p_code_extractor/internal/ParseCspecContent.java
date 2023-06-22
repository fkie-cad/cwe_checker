package internal;

/**
 * Most of the code below was inspired by Ghidra's source code at
 *     Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/lang/BasicCompilerSpec.java,
 *     Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/plugin/processors/sleigh/SleighLanguageProvider.java 
 * 
 * It extracts unaffected, killed by call and return registers for the given CPU architecture and adds them to the json output.
 * 
 * For the identification of the correct .cspec file, the processor name is extracted from Ghidra to find the processor's
 * corresponding .ldefs file. In the .ldefs file the language id and and compilerSpec id is used to determine the correct .cspec file.
 * 
 * If the correct .cpsec file was found, it iterates over the XML DOM to extract the above mentioned registers.
 * 
 * TODO: Since Ghidra 10.0 it should be a possible to extract the registers using the Ghidra API without parsing the .cspec file.
 * See issue 2357 in the Ghidra repository.
 * We should update the code below accordingly as soon as we bump the minimal Ghidra version to 10.0!
 */

import ghidra.xml.*;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

import org.xml.sax.*;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.framework.Application;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.CompilerSpecNotFoundException;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class ParseCspecContent {
    private static Exception parseException;
    private static LanguageID languageId;
    private static CompilerSpecID compilerSpecId;
    private static Program program;

    /**
     * 
     * @param ghidraProgram
     * @param conventions
     * @throws FileNotFoundException
     * 
     * Set the important parameters and handle the file extraction and parsing
     */
    public static void parseSpecs(Program ghidraProgram, HashMap<String, RegisterConvention> conventions) throws FileNotFoundException {
        program = ghidraProgram;
        languageId = program.getLanguageID();
        compilerSpecId = program.getCompilerSpec().getCompilerSpecID();

        ResourceFile ldefFile = getLdefFile();
        if(ldefFile != null) {
            XmlPullParser ldefParser = null;
        
            try {
                ldefParser = parseXmlFile(ldefFile);
            }
            catch (CompilerSpecNotFoundException e) {
                System.out.println(e);
            }

            String cspecFileName = parseLdefFile(ldefParser);
            ResourceFile cspecFile = getCspecFile(cspecFileName);
        
            if(cspecFile != null) {
                XmlPullParser cspecParser = null;

                try {
                    cspecParser = parseXmlFile(cspecFile);
                }
                catch (CompilerSpecNotFoundException e) {
                    System.out.println(e);
                }

                parseCspecFile(cspecParser, conventions);
            } else {
                throw new FileNotFoundException("Could not find .cspec file.");
            }
        } else {
            throw new FileNotFoundException("Could not find .ldef file.");
        }

    }


    /**
     * 
     * @param file: File in Ghidra directory
     * @return: XML parser for input file
     * @throws CompilerSpecNotFoundException
     * 
     * Handles all of the XML error handling and creates the Parser from the XMLPullParserFactory
     */
    public static XmlPullParser parseXmlFile(ResourceFile file) throws CompilerSpecNotFoundException {
        ErrorHandler errHandler = new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				parseException = exception;
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				parseException = exception;
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				Msg.warn(this, "Warning parsing '" + file + "'", exception);
			}
		};

        try {
            XmlPullParser parser = XmlPullParserFactory.create(file, errHandler, false);
            return parser;
        }
        catch (SleighException e) {
			parseException = e;
			Throwable cause = e.getCause();
			if (cause != null) {
				if (cause instanceof SAXException || cause instanceof IOException) {
					parseException = (Exception) cause;
				}
			}
		}
        catch (FileNotFoundException e) {
            parseException = e;
        }
        catch (IOException e) {
            parseException = e;
        }
        catch (SAXException e) {
			parseException = e;
        }
        
        if (parseException != null) {
            throw new CompilerSpecNotFoundException(
                languageId, 
                compilerSpecId, 
                file.getName(), 
                parseException
            );
        }
        
        return null;

    }


    /**
     * 
     * @return: resource file i.e. .ldef
     * 
     * Searches the Ghidra's directories for .ldef extension and returns the corresponding
     * file based on the processor name. In some cases the processor name has to be parsed
     * for correct matching.
     */
    public static ResourceFile getLdefFile() {
        String processorDef = String.format("%s.ldefs", program.getLanguage().getLanguageDescription().getProcessor().toString());
        if(processorDef.startsWith("MIPS") || processorDef.startsWith("AVR")) {
            processorDef = processorDef.toLowerCase();
        }
        if(processorDef.startsWith("PowerPC")) {
            processorDef = "ppc.ldefs";
        }
        for(ResourceFile file : Application.findFilesByExtensionInApplication(".ldefs")) {
            if(file.getName().equals(processorDef)) {
                return file;
            }
        }
        return null;
    }


    /**
     * 
     * @param parser: parser for .ldef file
     * @return: filename of .cspec file
     * 
     * Parses the .cspec filename from the .ldef file by
     * matching the language id. e.g. id = ARM:LE:32:v8
     * to analyse the correct language.
     */
    public static String parseLdefFile(XmlPullParser parser) {
        String cspecName = null;
        parser.start("language_definitions");
        while(parser.peek().isStart()) {
            XmlElement languageEnter = parser.peek();
            if(languageEnter.getAttribute("id").equals(languageId.getIdAsString())) {
                cspecName = getCompilerName(parser);
            } else {
                discardSubTree(parser);
            }
        }
        parser.end();

        return cspecName;
    }


    /**
     * 
     * @param parser
     * @return
     * 
     * Parses the compiler fields of the language and extracts the correct
     * compiler using the compilerSpec Id e.g. id = default
     * 
     * <compiler name="default" spec="ARM.cspec" id="default"/>
     */
    public static String getCompilerName(XmlPullParser parser) {
        String cspec = null;
        parser.start("language");
        while(parser.peek().isStart()) {
            XmlElement langProperty = parser.peek();
            if(langProperty.getName().equals("compiler")) {
                if(langProperty.getAttribute("id").equals(compilerSpecId.getIdAsString())) {
                    parser.start();
                    cspec = langProperty.getAttribute("spec");
                    parser.end();
                } else {
                    discardSubTree(parser);
                }
            } else {
                discardSubTree(parser);
            }
        }
        parser.end();
        return cspec;
    }


    /**
     * 
     * @param parser: parser for .cspec file
     * @param conventions
     * 
     * Searches the .cspec file for default_proto or prototype wrapper
     */
    public static void parseCspecFile(XmlPullParser parser, HashMap<String, RegisterConvention> conventions) {
        parser.start("compiler_spec");
        while(parser.peek().isStart()) {
            String field = parser.peek().getName();
            if(field.equals("default_proto") || field.equals("prototype")) {
                parsePrototype(parser, field, conventions);
            } else {
                discardSubTree(parser);
            }
        }
        parser.end();
    }


    /**
     * 
     * @param parser: parser for .cspec file
     * @param name: name of the wrapper
     * @param conventions
     * 
     * Gets registers based on wrapper name. The default_proto wrapper
     * is an additional wrapper around the default prototype. Therefore,
     * the function has to go one level deeper.
     */
    public static void parsePrototype(XmlPullParser parser, String name, HashMap<String, RegisterConvention> conventions) {
        RegisterConvention convention = new RegisterConvention();
        if(name.equals("default_proto")) {
            parser.start();
            getCconvRegister(parser, convention);
            parser.end();
        } else if(name.equals("prototype")) {
            getCconvRegister(parser, convention);
        }

        // Using the hashmap this way will simplify the addition of parameter registers which are not parsed here
        // as they are calling convention specific
        conventions.put(convention.getCconv(), convention);
    }


    /**
     * 
     * @param parser: parser for .cspec file
     * @param convention: convention object for later serialization
     * 
     * Sets the convention's unaffected, killed by call and return registers as well as the calling convention
     */
    public static void getCconvRegister(XmlPullParser parser, RegisterConvention convention) {
        XmlElement protoElement = parser.start();
        String cconv = protoElement.getAttribute("name");
        convention.setCconv(cconv);
        while(parser.peek().isStart()) {
            XmlElement entries = parser.peek();
            if(entries.getName().equals("input")) {
                parseInput(parser, convention);
            } else if(entries.getName().equals("unaffected")) {
                convention.setUnaffected(getRegisters(parser));
            } else if (entries.getName().equals("killedbycall")) {
                convention.setKilledByCall(getRegisters(parser));
            } else if (entries.getName().equals("output")) {
                parseOutput(parser, convention);
            } else {
                discardSubTree(parser);
            }
        }
        parser.end(protoElement);
    }

    /**
     * 
     * @param parser: parser for .cspec file
     * @param integerRegisters: the list of known integer registers
     * @param floatRegisters: the list of known float registers
     *
     * Parses a single parameter from the given parser and adds it either to the list of integer registers
     * or to the list of float registers
     */
    public static void parseSingleRegister(XmlPullParser parser, ArrayList<String> integerRegisters, ArrayList<String> floatRegisters) {
        XmlElement pentry = parser.peek();
        parser.start("pentry");
        XmlElement entry = parser.peek();
        if(entry.getName().equals("register")) {
            parser.start("register");
            if(isFloatRegister(pentry)) {
                floatRegisters.add(entry.getAttribute("name"));
            } else {
                integerRegisters.add(entry.getAttribute("name"));
            }
            parser.end();
        } else {
            discardSubTree(parser);
        }
        parser.end();
    }

    /**
     * 
     * @param parser: parser for .cspec file
     * @param convention: convention object for later serialization
     * 
     * Parses the parameter registers for an external symbol.
     * Differentiates between integer and float registers.
     */
    public static void parseInput(XmlPullParser parser, RegisterConvention convention) {
        ArrayList<String> integerRegisters = new ArrayList<String>();
        ArrayList<String> floatRegisters = new ArrayList<String>(); 
        parser.start("input");
        while(parser.peek().isStart()) {
            if(parser.softStart("group") != null) {
                // The x86-64-win.cspec file has some registers that are additionally nested in "group" items
                while(parser.peek().isStart()) {
                    parseSingleRegister(parser, integerRegisters, floatRegisters);
                }
                parser.end();
            } else {
                parseSingleRegister(parser, integerRegisters, floatRegisters);
            }
        }
        parser.end();

        convention.setFloatParameter(floatRegisters);
        convention.setIntegerParameter(integerRegisters);
    }

    /**
     * 
     * @param pentry: Parameter register entry
     * @return: indicates whether the current entry is a float register.
     */
    public static Boolean isFloatRegister(XmlElement pentry) {
        if(pentry.hasAttribute("metatype")) {
            if(pentry.getAttribute("metatype").equals("float")) {
                return true;
            }
        }

        return false;
    }

    /**
     * 
     * @param parser: parser for .cspec file
     * @return: list of return registers
     * 
     * Parses the output and pentry wrapper to access the return register fields
     */
    public static void parseOutput(XmlPullParser parser, RegisterConvention convention) {
        ArrayList<String> integerRegisters = new ArrayList<String>();
        ArrayList<String> floatRegisters = new ArrayList<String>();
        parser.start("output");
        while(parser.peek().isStart()) {
            XmlElement pentry = parser.peek();
            parser.start("pentry");
            XmlElement entry = parser.peek();
            if(entry.getName().equals("register")) {
                parser.start("register");
                if(isFloatRegister(pentry)) {
                    floatRegisters.add(entry.getAttribute("name"));
                } else {
                    integerRegisters.add(entry.getAttribute("name"));
                }
                parser.end();
            } else {
                discardSubTree(parser);
            }
            parser.end();
        }
        parser.end();

        convention.setReturn(integerRegisters);
        convention.setFloatReturn(floatRegisters);
    }


    /**
     * 
     * @param parser: parser for .cspec file
     * @return: either killed by call or unaffected registers
     * 
     * Parses killed by call or unaffected registers and ingnores varnode types
     */
    public static ArrayList<String> getRegisters(XmlPullParser parser) {
        ArrayList<String> registers = new ArrayList<String>(); 
        parser.start();
        while(parser.peek().isStart()) {
            XmlElement type = parser.peek();
            if(type.getName().equals("register")) {
                parser.start();
                registers.add(type.getAttribute("name"));
                parser.end();
            } else if(type.getName().equals("varnode")) {
                discardSubTree(parser);
            }
        }
        parser.end();

        return registers;
    }


    /**
     * 
     * @param filename: .cspec filename
     * @return: .cspec file
     * 
     * Return the .cspec file for a given filename
     */
    public static ResourceFile getCspecFile(String filename) {
        for(ResourceFile file : Application.findFilesByExtensionInApplication(".cspec")) {
            if(file.getName().equals(filename)) {
                return file;
            }
        }
        return null;
    }


    /**
     * 
     * @param parser: xml parser
     * 
     * discards XML subtrees if they do not contain necessary information.
     * Simply used as a shortcut.
     */
    public static void discardSubTree(XmlPullParser parser) {
        XmlElement el = parser.start();
        parser.discardSubTree(el);
    }
}
