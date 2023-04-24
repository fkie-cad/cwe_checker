import ghidra.program.model.listing.Program;
import ghidra.program.model.data.DataOrganization;

/**
 * Wrapper class for datatype properties.
 * 
 * This class is used for clean and simple serialization.
 */
public class DatatypeProperties {
    private int charSize;
    private int doubleSize;
    private int floatSize;
    private int integerSize;
    private int longDoubleSize;
    private int longLongSize;
    private int longSize;
    private int pointerSize;
    private int shortSize;

    public DatatypeProperties(Program currentProgram) {
        DataOrganization dataOrga = currentProgram.getDataTypeManager().getDataOrganization();

        this.charSize = dataOrga.getCharSize();
        this.doubleSize = dataOrga.getDoubleSize();
        this.floatSize = dataOrga.getFloatSize();
        this.integerSize = dataOrga.getIntegerSize();
        this.longDoubleSize = dataOrga.getLongDoubleSize();
        this.longLongSize = dataOrga.getLongLongSize();
        this.longSize = dataOrga.getLongSize();
        this.pointerSize = dataOrga.getPointerSize();
        this.shortSize = dataOrga.getShortSize();

    }
}