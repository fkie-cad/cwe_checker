package term;

import com.google.gson.annotations.SerializedName;

public class Tid {
    @SerializedName("id")
    private String id;
    @SerializedName("address")
    private String address;

    public Tid() {
    }

    public Tid(String id, String address) {
        this.setId(id);
        this.setAddress(address);
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }
}
