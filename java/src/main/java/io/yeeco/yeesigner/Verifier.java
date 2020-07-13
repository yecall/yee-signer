package io.yeeco.yeesigner;

public class Verifier {

    private long pointer;

    public static Verifier fromPublicKey(byte[] publicKey) throws SignerException {

        byte[] error = new byte[1];
        long pointer = JNI.verifierFromPublicKey(publicKey, error);
        ErrorUtils.checkErrorCode(error[0]);

        Verifier instance = new Verifier();
        instance.pointer = pointer;
        return instance;
    }


    public void verify(byte[] signature, byte[] message, byte[] ctx) throws SignerException {
        byte[] error = new byte[1];
        JNI.verify(pointer, signature, message, ctx, error);
        ErrorUtils.checkErrorCode(error[0]);
    }

    @Override
    protected void finalize(){
        byte[] error = new byte[1];
        JNI.verifierFree(pointer, error);
    }
}
