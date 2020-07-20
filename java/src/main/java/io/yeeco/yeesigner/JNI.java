package io.yeeco.yeesigner;

public class JNI {

    public native static long keyPairFromMiniSecretKey(byte[] miniSecretKey, byte[] error);

    public native static long keyPairFromSecretKey(byte[] secretKey, byte[] error);

    public native static void publicKey(long keyPair, byte[] publicKey, byte[] error);

    public native static void secretKey(long keyPair, byte[] secretKey, byte[] error);

    public native static void sign(long keyPair, byte[] message, byte[] signature, byte[] ctx, byte[] error);

    public native static void keyPairFree(long keyPair, byte[] error);

    public native static long verifierFromPublicKey(byte[] publicKey, byte[] error);

    public native static void verify(long verifier, byte[] signature, byte[] message, byte[] ctx, byte[] error);

    public native static void verifierFree(long verifier, byte[] error);

    public native static long buildCall(byte[] json, byte[] error);

    public native static void callFree(long call, byte[] error);

    public native static long buildTx(byte[] secretKey, long nonce, long period, long current, byte[] currentHash, long call, byte[] error);

    public native static void txFree(long tx, byte[] error);

    public native static long txEncode(long tx, byte[] error);

    public native static long vecLen(long vec, byte[] error);

    public native static void vecCopy(long vec, byte[] out, byte[] error);

    public native static void vecFree(long vec, byte[] error);

    public native static long txDecode(byte[] raw, byte[] error);

    public native static void verifyTx(long tx, byte[] currentHash, byte[] error);

}
