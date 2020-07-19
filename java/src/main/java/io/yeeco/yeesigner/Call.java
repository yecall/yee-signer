package io.yeeco.yeesigner;

public class Call {

    private long pointer;

    public static Call newCall(String json) throws SignerException {

        byte[] error = new byte[1];
        long pointer = JNI.buildCall(json.getBytes(), error);
        ErrorUtils.checkErrorCode(error[0]);

        Call instance = new Call();
        instance.pointer = pointer;
        return instance;
    }

    public long getPointer() {
        return pointer;
    }

    @Override
    protected void finalize(){
        byte[] error = new byte[1];
        JNI.callFree(pointer, error);
    }

}
