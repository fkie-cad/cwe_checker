package bil;

import com.google.gson.annotations.SerializedName;

public class DatatypeProperties {
    @SerializedName("char_size")
    private int charSize;
    @SerializedName("double_size")
    private int doubleSize;
    @SerializedName("float_size")
    private int floatSize;
    @SerializedName("integer_size")
    private int integerSize;
    @SerializedName("long_double_size")
    private int longDoubleSize;
    @SerializedName("long_long_size")
    private int longLongSize;
    @SerializedName("long_size")
    private int longSize;
    @SerializedName("pointer_size")
    private int pointerSize;
    @SerializedName("short_size")
    private int shortSize;

    public DatatypeProperties(
        int charSize,
        int doubleSize,
        int floatSize,
        int integerSize,
        int longDoubleSize,
        int longLongSize,
        int longSize,
        int pointerSize,
        int shortSize
    ) {
        this.setCharSize(charSize);
        this.setDoubleSize(doubleSize);
        this.setFloatSize(floatSize);
        this.setIntegerSize(integerSize);
        this.setLongDoubleSize(longDoubleSize);
        this.setLongLongSize(longLongSize);
        this.setLongSize(longSize);
        this.setPointerSize(pointerSize);
        this.setShortSize(shortSize);
    }

    public void setCharSize(int size) {
        this.charSize = size;
    }

    public void setDoubleSize(int size) {
        this.doubleSize = size;
    }

    public void setFloatSize(int size) {
        this.floatSize = size;
    }

    public void setIntegerSize(int size) {
        this.integerSize = size;
    }

    public void setLongDoubleSize(int size) {
        this.longDoubleSize = size;
    }

    public void setLongLongSize(int size) {
        this.longLongSize = size;
    }

    public void setLongSize(int size) {
        this.longSize = size;
    }

    public void setPointerSize(int size) {
        this.pointerSize = size;
    }

    public void setShortSize(int size) {
        this.shortSize = size;
    }
}

