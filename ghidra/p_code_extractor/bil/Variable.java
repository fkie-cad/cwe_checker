package bil;

import com.google.gson.annotations.SerializedName;

public class Variable {

    @SerializedName("name")
    private String name;
    @SerializedName("value")
    private String value;
    @SerializedName("address")
    private String address;
    @SerializedName("size")
    private long size;
    @SerializedName("is_virtual")
    private Boolean isVirtual;

    public Variable() {
    }

    public Variable(String name, long size, Boolean is_virtual) {
        this.setName(name);
        this.setSize(size);
        this.setIsVirtual(is_virtual);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public long getSize() {
        return size;
    }

    public void setSize(long size) {
        this.size = size;
    }

    public Boolean getIsVirtual() {
        return isVirtual;
    }

    public void setIsVirtual(Boolean is_virtual) {
        this.isVirtual = is_virtual;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }
}
