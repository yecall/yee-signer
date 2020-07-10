package io.yeeco.yeesigner;

public class KeyPair {

    public final static int PUBLIC_KEY_LENGTH = 32;
    public final static int SECRET_KEY_LENGTH = 64;
    public final static int MINI_SECRET_KEY_LENGTH = 32;
    public final static int SIGNATURE_KEY_LENGTH = 64;

    private long pointer;

    public static KeyPair fromMiniSecretKey(byte[] miniSecretKey) throws SignerException {

        byte[] error = new byte[1];
        long pointer = JNI.keyPairFromMiniSecretKey(miniSecretKey, error);
        ErrorUtils.checkErrorCode(error[0]);

        KeyPair instance = new KeyPair();
        instance.pointer = pointer;
        return instance;
    }

    public static KeyPair fromSecretKey(byte[] secretKey) throws SignerException {
        byte[] error = new byte[1];
        long pointer = JNI.keyPairFromSecretKey(secretKey, error);
        ErrorUtils.checkErrorCode(error[0]);

        KeyPair instance = new KeyPair();
        instance.pointer = pointer;
        return instance;
    }

    public byte[] getPublicKey() throws SignerException {

        byte[] publicKey = new byte[PUBLIC_KEY_LENGTH];
        byte[] error = new byte[1];
        JNI.publicKey(pointer, publicKey, error);
        ErrorUtils.checkErrorCode(error[0]);

        return publicKey;
    }

    public byte[] getSecretKey() throws SignerException {
        byte[] secretKey = new byte[SECRET_KEY_LENGTH];
        byte[] error = new byte[1];
        JNI.secretKey(pointer, secretKey, error);
        ErrorUtils.checkErrorCode(error[0]);

        return secretKey;
    }

    public byte[] sign(byte[] message, byte[] ctx) throws SignerException {
        byte[] signature = new byte[SIGNATURE_KEY_LENGTH];
        byte[] error = new byte[1];
        JNI.sign(pointer, message, signature, ctx, error);
        ErrorUtils.checkErrorCode(error[0]);

        return signature;
    }

    @Override
    protected void finalize(){
        byte[] error = new byte[1];
        JNI.keyPairFree(pointer, error);
    }

}
