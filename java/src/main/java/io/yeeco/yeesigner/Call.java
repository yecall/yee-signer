package io.yeeco.yeesigner;

public class Call {

    private long pointer;
    private int module;
    private int method;

    public static Call newBalanceTransferCall(byte[] dest, long value) throws SignerException {

        byte[] error = new byte[1];
        byte[] module = new byte[1];
        byte[] method = new byte[1];
        long pointer = JNI.buildCallBalanceTransfer(dest, value, module, method, error);
        ErrorUtils.checkErrorCode(error[0]);

        Call instance = new Call();
        instance.pointer = pointer;
        instance.module = module[0];
        instance.method = method[0];
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
