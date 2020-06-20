package io.yeeco.yeesigner;

public class JNI {

    public native static long keyPairFromMiniSecretKey(byte[] miniSecretKey, byte[] error);

    public native static long keyPairFromSecretKey(byte[] secretKey, byte[] error);

    public native static void publicKey(long keyPair, byte[] publicKey, byte[] error);

    public native static void secretKey(long keyPair, byte[] secretKey, byte[] error);

    public native static void sign(long keyPair, byte[] message, byte[] signature, byte[] error);

    public native static void keyPairFree(long keyPair, byte[] error);

    public native static long verifierFromPublicKey(byte[] publicKey, byte[] error);

    public native static void verify(long verifier, byte[] signature, byte[] message, byte[] error);

    public native static void verifierFree(long verifier, byte[] error);

}
