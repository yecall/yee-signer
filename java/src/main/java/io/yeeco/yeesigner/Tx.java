package io.yeeco.yeesigner;

public class Tx {

    private long pointer;
    private int method;
    private int module;

    public static Tx buildTx(byte[] secretKey, long nonce, long period, long current, byte[] currentHash, Call call) throws SignerException {

        byte[] error = new byte[1];
        long pointer = JNI.buildTx(secretKey, nonce, period, current, currentHash, call.getPointer(), call.getModule(), call.getMethod(), error);
        ErrorUtils.checkErrorCode(error[0]);

        Tx instance = new Tx();
        instance.pointer = pointer;
        instance.module = call.getModule();
        instance.method = call.getMethod();
        return instance;
    }

    public static Tx decode(byte[] raw) throws SignerException {

        byte[] error = new byte[1];
        byte[] module = new byte[1];
        byte[] method = new byte[1];
        long pointer = JNI.txDecode(raw, module, method, error);
        ErrorUtils.checkErrorCode(error[0]);

        Tx instance = new Tx();
        instance.pointer = pointer;
        instance.module = module[0];
        instance.method = method[0];

        return instance;
    }

    public byte[] encode() throws SignerException {

        byte[] error = new byte[1];
        int len = (int) JNI.txLength(pointer, module, method, error);
        ErrorUtils.checkErrorCode(error[0]);

        byte[] encode = new byte[len];
        error = new byte[1];
        JNI.txEncode(pointer, module, method, encode, error);
        ErrorUtils.checkErrorCode(error[0]);

        return encode;
    }

    public void verify(byte[] currentHash) throws SignerException {

        byte[] error = new byte[1];
        JNI.verifyTx(pointer, module, method, currentHash, error);
        ErrorUtils.checkErrorCode(error[0]);

    }

    public int getMethod() {
        return method;
    }

    public int getModule() {
        return module;
    }

    @Override
    protected void finalize() {
        byte[] error = new byte[1];
        JNI.txFree(pointer, module, method, error);
    }

}
