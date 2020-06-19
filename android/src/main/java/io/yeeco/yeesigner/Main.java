package io.yeeco.yeesigner;

import org.apache.commons.codec.binary.Hex;

public class Main {

    static {
        System.load("/Users/gb/Dev/workspace_yeeco/yee-signer/target/debug/libyee_signer.dylib");
    }

    public static void main(String[] args) throws Exception {

        testKeyPairFromMiniSecretKey();
        testKeyPairFromSecretKey();
        testKeyPairSignVerify();
        testKeyPairSignVerifyFail();

    }

    private static void testKeyPairFromMiniSecretKey() throws Exception {

        byte[] miniSecretKey = Hex.decodeHex("579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae");
        KeyPair keyPair = KeyPair.fromMiniSecretKey(miniSecretKey);

        byte[] publicKey = keyPair.getPublicKey();
        System.out.println(Hex.encodeHexString(publicKey));

        byte[] secretKey = keyPair.getSecretKey();
        System.out.println(Hex.encodeHexString(secretKey));

    }

    private static void testKeyPairFromSecretKey() throws Exception {

        byte[] miniSecretKey = Hex.decodeHex("bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b");
        KeyPair keyPair = KeyPair.fromSecretKey(miniSecretKey);

        byte[] publicKey = keyPair.getPublicKey();
        System.out.println(Hex.encodeHexString(publicKey));

        byte[] secretKey = keyPair.getSecretKey();
        System.out.println(Hex.encodeHexString(secretKey));
    }

    private static void testKeyPairSignVerify() throws Exception {

        byte[] miniSecretKey = Hex.decodeHex("bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b");
        KeyPair keyPair = KeyPair.fromSecretKey(miniSecretKey);

        byte[] message = new byte[]{1,2,3};

        byte[] signature = keyPair.sign(message);

        System.out.println(Hex.encodeHexString(signature));

        Verifier verifier = Verifier.fromPublicKey(keyPair.getPublicKey());

        verifier.verify(signature, message);

    }

    private static void testKeyPairSignVerifyFail() throws Exception {

        byte[] miniSecretKey = Hex.decodeHex("bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b");
        KeyPair keyPair = KeyPair.fromSecretKey(miniSecretKey);

        byte[] message = new byte[]{1,2,3};

        byte[] signature = keyPair.sign(message);

        System.out.println(Hex.encodeHexString(signature));

        Verifier verifier = Verifier.fromPublicKey(keyPair.getPublicKey());

        signature[0] = 0;

        try {
            verifier.verify(signature, message);
        }catch (Exception e){
            System.out.println(e.getMessage());
        }

    }

}
