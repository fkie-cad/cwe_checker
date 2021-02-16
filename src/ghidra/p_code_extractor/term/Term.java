package term;

import com.google.gson.annotations.SerializedName;

public class Term<T> {
    @SerializedName("tid")
    private Tid tid;
    @SerializedName("term")
    private T term;

    public Term() {
    }

    public Term(Tid tid, T term) {
        this.setTid(tid);
        this.setTerm(term);
    }

    public Tid getTid() {
        return tid;
    }

    public void setTid(Tid tid) {
        this.tid = tid;
    }

    public T getTerm() {
        return term;
    }

    public void setTerm(T term) {
        this.term = term;
    }
}
