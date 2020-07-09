import io.yeeco.yeesigner.*;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.io.*;

import static org.junit.Assert.assertEquals;

public class TxTest {

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
    public void testBuildTx() throws Exception {

        // transfer dest address: 33 bytes, 0xFF + public key
        byte[] dest = Hex.decodeHex("FF927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70");

        // transfer value
        long value = 1000;
        Call call = Call.newBalanceTransferCall(dest, value);

        // sender secret key
        byte[] secret_key = Hex.decodeHex("0b58d672927e01314d624fcb834a0f04b554f37640e0a4c342029a996ec1450bac8afb286e210d3afbfb8fd429129bd33329baaea6b919c92651c072c59d2408");

        // sender nonce
        long nonce = 0;

        // era period: use 64
        long period = 64;

        // era current: the block number of the best block
        long current = 26491;

        // era current hash: the block hash of the best block
        byte[] current_hash = Hex.decodeHex("c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe13");

        Tx tx = Tx.buildTx(secret_key, nonce, period, current, current_hash, call);

        // get the raw tx
        byte[] encode = tx.encode();

        //System.out.println(Hex.encodeHexString(encode));

        assertEquals(call.getModule(), 4);
        assertEquals(call.getMethod(), 0);

        assertEquals(encode.length, 140);

    }

    @Test
    public void testVerifyTx() throws Exception {

        byte[] raw = Hex.decodeHex("290281ffb03481c9f7e36ddaf3fd206ff3eea011eb5c431778ece03f99f2094d352a7209168247df3d0a8f0a33da4b86c1de80dc53ab9fe46ae9289fece568e0cc8b2a4383b250e09211171646ff396ae201855ced3361e7f8551dba4a1b5434c28c8d8800b5030400ff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70a10f");

        Tx tx = Tx.decode(raw);

        assertEquals(tx.getModule(), 4);
        assertEquals(tx.getMethod(), 0);

        byte[] current_hash = Hex.decodeHex("c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe13");

        tx.verify(current_hash);

    }

    @Test
    public void testVerifyTxFail() throws Exception {

        byte[] raw = Hex.decodeHex("290281ffb03481c9f7e36ddaf3fd206ff3eea011eb5c431778ece03f99f2094d352a7209168247df3d0a8f0a33da4b86c1de80dc53ab9fe46ae9289fece568e0cc8b2a4383b250e09211171646ff396ae201855ced3361e7f8551dba4a1b5434c28c8d8800b5030400ff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70a10f");

        Tx tx = Tx.decode(raw);

        assertEquals(tx.getModule(), 4);
        assertEquals(tx.getMethod(), 0);

        byte[] current_hash = Hex.decodeHex("c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe14");

        boolean ok = true;
        try {
            tx.verify(current_hash);
        }catch (Exception e){
            ok = false;
        }

        assertEquals(ok, false);

    }


}