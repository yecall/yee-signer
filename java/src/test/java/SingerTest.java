import io.yeeco.yeesigner.KeyPair;
import io.yeeco.yeesigner.SignerException;
import io.yeeco.yeesigner.Verifier;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.io.*;

import static org.junit.Assert.assertEquals;

public class SingerTest {

    static {

        try {
            String libFileName = "jniLibs/" + (System.getProperty("os.name").toLowerCase().contains("mac") ? "libyee_signer.dylib" : "libyee_signer.so");

            File oriFile = new File(libFileName);

            InputStream is = new FileInputStream(oriFile);
            File file = File.createTempFile("lib", ".so");
            OutputStream os = new FileOutputStream(file);
            byte[] buffer = new byte[1024];
            int length;
            while ((length = is.read(buffer)) != -1) {
                os.write(buffer, 0, length);
            }
            is.close();
            os.close();

            System.load(file.getAbsolutePath());
            file.deleteOnExit();

        }catch (Exception e){

        }
    }

    @Test
    public void testKeyPairFromMiniSecretKey() throws Exception {

        byte[] miniSecretKey = Hex.decodeHex("579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae");
        KeyPair keyPair = KeyPair.fromMiniSecretKey(miniSecretKey);

        byte[] publicKey = keyPair.getPublicKey();
        assertEquals(Hex.encodeHexString(publicKey), "4ef0125fab173ceb93ce4c2a97e6824396240101b9c7220e3fd63e3a2282cf20");

        byte[] secretKey = keyPair.getSecretKey();
        assertEquals(Hex.encodeHexString(secretKey), "bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b");

    }
    @Test
    public void testKeyPairFromMiniSecretKeyFail() throws Exception {

        byte[] miniSecretKey = Hex.decodeHex("579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43");

        String message = null;
        try {
            KeyPair keyPair = KeyPair.fromMiniSecretKey(miniSecretKey);
        }catch (SignerException e){
            message = e.getMessage();
        }

        assertEquals(message, "invalid mini secret key");
    }


    @Test
    public void testKeyPairFromSecretKey() throws Exception {

        byte[] miniSecretKey = Hex.decodeHex("bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b");
        KeyPair keyPair = KeyPair.fromSecretKey(miniSecretKey);

        byte[] publicKey = keyPair.getPublicKey();
        assertEquals(Hex.encodeHexString(publicKey), "4ef0125fab173ceb93ce4c2a97e6824396240101b9c7220e3fd63e3a2282cf20");

        byte[] secretKey = keyPair.getSecretKey();
        assertEquals(Hex.encodeHexString(secretKey), "bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b");
    }

    @Test
    public void testKeyPairSignVerify() throws Exception {

        byte[] miniSecretKey = Hex.decodeHex("bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b");
        KeyPair keyPair = KeyPair.fromSecretKey(miniSecretKey);

        byte[] message = new byte[]{1, 2, 3};

        byte[] signature = keyPair.sign(message);

        Verifier verifier = Verifier.fromPublicKey(keyPair.getPublicKey());

        verifier.verify(signature, message);

    }

    @Test
    public void testKeyPairSignVerifyFail() throws Exception {

        byte[] miniSecretKey = Hex.decodeHex("bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b");
        KeyPair keyPair = KeyPair.fromSecretKey(miniSecretKey);

        byte[] message = new byte[]{1, 2, 3};

        byte[] signature = keyPair.sign(message);

        Verifier verifier = Verifier.fromPublicKey(keyPair.getPublicKey());

        signature[0] = 0;

        boolean ok = false;
        try {
            verifier.verify(signature, message);
            ok = true;
        } catch (Exception e) {
        }

        assertEquals(ok, false);

    }

}