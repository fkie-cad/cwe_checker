package bil;

public interface ExecutionType {

    public String getType();

    enum OtherType implements ExecutionType {

        COPY("COPY"),
        LOAD("LOAD"),
        STORE("STORE"),
        PIECE("PIECE"),
        SUBPIECE("SUBPIECE");

        private String type;

        private OtherType(String type) {
            this.type = type;
        }

        @Override
        public String getType() {
            return this.type;
        }
    }

    enum BinOpType implements ExecutionType {

        INT_EQUAL("INT_EQUAL"),
        INT_NOTEQUAL("INT_NOTEQUAL"),
        INT_LESS("INT_LESS"),
        INT_SLESS("INT_SLESS"),
        INT_LESSEQUAL("INT_LESSEQUAL"),
        INT_SLESSEQUAL("INT_SLESSEQUAL"),
        INT_ADD("INT_ADD"),
        INT_SUB("INT_SUB"),
        INT_CARRY("INT_CARRY"),
        INT_SCARRY("INT_SCARRY"),
        INT_SBORROW("INT_SBORROW"),
        INT_XOR("INT_XOR"),
        INT_AND("INT_AND"),
        INT_OR("INT_OR"),
        INT_LEFT("INT_LEFT"),
        INT_RIGHT("INT_RIGHT"),
        INT_SRIGHT("INT_SRIGHT"),
        INT_MULT("INT_MULT"),
        INT_DIV("INT_DIV"),
        INT_REM("INT_REM"),
        INT_SDIV("INT_SDIV"),
        INT_SREM("INT_SREM"),
        BOOL_XOR("BOOL_XOR"),
        BOOL_AND("BOOL_AND"),
        BOOL_OR("BOOL_OR"),
        FLOAT_EQUAL("FLOAT_EQUAL"),
        FLOAT_NOTEQUAL("FLOAT_NOTEQUAL"),
        FLOAT_LESS("FLOAT_LESS"),
        FLOAT_LESSEQUAL("FLOAT_LESSEQUAL"),
        FLOAT_ADD("FLOAT_ADD"),
        FLOAT_SUB("FLOAT_SUB"),
        FLOAT_MULT("FLOAT_MULT"),
        FLOAT_DIV("FLOAT_DIV");

        private String type;

        private BinOpType(String type) {
            this.type = type;
        }

        @Override
        public String getType() {
            return this.type;
        }

    }

    enum UnOpType implements ExecutionType {

        INT_NEGATE("INT_NEGATE"),
        INT_2COMP("INT_2COMP"),
        BOOL_NEGATE("BOOL_NEGATE"),
        FLOAT_NEG("FLOAT_NEG"),
        FLOAT_ABS("FLOAT_ABS"),
        FLOAT_SQRT("FLOAT_SQRT"),
        FLOAT_CEIL("FLOAT_CEIL"),
        FLOAT_FLOOR("FLOAT_FLOOR"),
        FLOAT_ROUND("FLOAT_ROUND");

        private String type;

        private UnOpType(String type) {
            this.type = type;
        }

        @Override
        public String getType() {
            return this.type;
        }

    }

    enum CastType implements ExecutionType {

        INT_ZEXT("INT_ZEXT"),
        INT_SEXT("INT_SEXT"),
        INT2FLOAT("INT2FLOAT"),
        FLOAT2FLOAT("FLOAT2FLOAT"),
        TRUNC("TRUNC"),
        FLOAT_NAN("FLOAT_NAN");

        private String type;

        private CastType(String type) {
            this.type = type;
        }

        @Override
        public String getType() {
            return this.type;
        }
    }

    enum JmpType implements ExecutionType {
        CALL("CALL"),
        GOTO("GOTO"),
        RETURN("RETURN");

        private String type;

        private JmpType(String type) {
            this.type = type;
        }

        @Override
        public String getType() {
            return this.type;
        }
    }
}
