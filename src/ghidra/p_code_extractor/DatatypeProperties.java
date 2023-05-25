import ghidra.program.model.listing.Program;
import ghidra.program.model.data.DataOrganization;

/**
 * Wrapper class for datatype properties.
 * 
 * This class is used for clean and simple serialization.
 */
public class DatatypeProperties {
    private int char_size;
    private int double_size;
    private int float_size;
    private int integer_size;
    private int long_double_size;
    private int long_long_size;
    private int long_size;
    private int pointer_size;
    private int short_size;

    public DatatypeProperties(Program currentProgram) {
        DataOrganization dataOrga = currentProgram.getDataTypeManager().getDataOrganization();

        this.char_size = dataOrga.getCharSize();
        this.double_size = dataOrga.getDoubleSize();
        this.float_size = dataOrga.getFloatSize();
        this.integer_size = dataOrga.getIntegerSize();
        this.long_double_size = dataOrga.getLongDoubleSize();
        this.long_long_size = dataOrga.getLongLongSize();
        this.long_size = dataOrga.getLongSize();
        this.pointer_size = dataOrga.getPointerSize();
        this.short_size = dataOrga.getShortSize();

    }
}