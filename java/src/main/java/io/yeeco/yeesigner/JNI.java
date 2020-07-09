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

    public native static long buildCallBalanceTransfer(byte[] dest, long value, byte[] module, byte[] method, byte[] error);

    public native static void callFree(long call, int module, int method, byte[] error);

    public native static long buildTx(byte[] secretKey, long nonce, long period, long current, byte[] currentHash, long call, int module, int method, byte[] error);

    public native static void txFree(long tx, int module, int method, byte[] error);

    public native static long txLength(long tx, int module, int method, byte[] error);

    public native static void txEncode(long tx, int module, int method, byte[] buffer, byte[] error);

    public native static long txDecode(byte[] raw, byte[] module, byte[] method, byte[] error);

    public native static void verifyTx(long tx, int module, int method, byte[] currentHash, byte[] error);

}
