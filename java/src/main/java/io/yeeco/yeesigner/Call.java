package io.yeeco.yeesigner;

public class Call {

    private long pointer;
    private int module;
    private int method;

    public static Call newCall(int module, int method, String params) throws SignerException {

        byte[] error = new byte[1];
        long pointer = JNI.buildCall(module, method, params.getBytes(), error);
        ErrorUtils.checkErrorCode(error[0]);

        Call instance = new Call();
        instance.pointer = pointer;
        instance.module = module;
        instance.method = method;
        return instance;
    }

    public long getPointer() {
        return pointer;
    }

    public int getModule() {
        return module;
    }

    public int getMethod() {
        return method;
    }

    @Override
    protected void finalize(){
        byte[] error = new byte[1];
        JNI.callFree(pointer, module, method, error);
    }

}
