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

        // params json
        // dest:  address: 33 bytes, 0xFF + public key
        // value: transfer value
        String json = "{\"module\":4, \"method\":0, \"params\":{\"dest\":\"0xFF927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70\",\"value\":1000}}";
        Call call = Call.newCall(json);

        // sender secret key
        byte[] secretKey = Hex.decodeHex("0b58d672927e01314d624fcb834a0f04b554f37640e0a4c342029a996ec1450bac8afb286e210d3afbfb8fd429129bd33329baaea6b919c92651c072c59d2408");

        // sender nonce
        long nonce = 0;

        // era period: use 64
        long period = 64;

        // era current: the block number of the best block
        long current = 26491;

        // era current hash: the block hash of the best block
        byte[] currentHash = Hex.decodeHex("c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe13");

        Tx tx = Tx.buildTx(secretKey, nonce, period, current, currentHash, call);

        // get the raw tx
        byte[] encode = tx.encode();

        System.out.println(Hex.encodeHexString(encode));

        assertEquals(encode.length, 140);

    }

    @Test
    public void testBuildTx2() throws Exception {

        // params json
        // addresses: array of address: 33 bytes, 0xFF + public key

        String json = "{\"module\":11, \"method\":1, \"params\":{\"addresses\":[\"0xffa6158c2b928d5d495922366ad9b4339a023366b322fb22f4db12751e0ea93f5c\"]}}";
        Call call = Call.newCall(json);

        // sender secret key
        byte[] secretKey = Hex.decodeHex("0b58d672927e01314d624fcb834a0f04b554f37640e0a4c342029a996ec1450bac8afb286e210d3afbfb8fd429129bd33329baaea6b919c92651c072c59d2408");

        // sender nonce
        long nonce = 0;

        // era period: use 64
        long period = 64;

        // era current: the block number of the best block
        long current = 26491;

        // era current hash: the block hash of the best block
        byte[] currentHash = Hex.decodeHex("c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe13");

        Tx tx = Tx.buildTx(secretKey, nonce, period, current, currentHash, call);

        // get the raw tx
        byte[] encode = tx.encode();

        System.out.println(Hex.encodeHexString(encode));

        assertEquals(encode.length, 139);

    }

    @Test
    public void testVerifyTx() throws Exception {

        byte[] raw = Hex.decodeHex("290281ff505b18b2457d210cca1b922cb8059f26d71a5f7e9a47dd05057ab5b53593726f2675f1d0fc18853845f59c012cdfecd10134d6c9312ed5cd0f64908f2c0b1439b996384b5ada3f8db54517d81bb0d07aa6cf101703d23d4a50222b791741110600b5030400ff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70a10f");

        Tx tx = Tx.decode(raw);

        byte[] currentHash = Hex.decodeHex("c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe13");

        tx.verify(currentHash);

    }

    @Test
    public void testVerifyTx2() throws Exception {

        byte[] raw = Hex.decodeHex("250281ff505b18b2457d210cca1b922cb8059f26d71a5f7e9a47dd05057ab5b53593726fa2dc5a9760131feac59cfc07312f7e65836ffcc9dbeeff0c96ae380d45a3a21c484d0cf3d371abba5d74dccd5dae6f893ca1f5b57a9b210b5d23d1687f92b10900b5030b0104ffa6158c2b928d5d495922366ad9b4339a023366b322fb22f4db12751e0ea93f5c");

        Tx tx = Tx.decode(raw);

        byte[] currentHash = Hex.decodeHex("c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe13");

        tx.verify(currentHash);

    }


    @Test
    public void testVerifyTxFail() throws Exception {

        byte[] raw = Hex.decodeHex("290281ff505b18b2457d210cca1b922cb8059f26d71a5f7e9a47dd05057ab5b53593726f2675f1d0fc18853845f59c012cdfecd10134d6c9312ed5cd0f64908f2c0b1439b996384b5ada3f8db54517d81bb0d07aa6cf101703d23d4a50222b791741110600b5030400ff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70a10f");

        Tx tx = Tx.decode(raw);

        byte[] currentHash = Hex.decodeHex("c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe14");

        boolean ok = true;
        try {
            tx.verify(currentHash);
        }catch (Exception e){
            ok = false;
        }

        assertEquals(ok, false);

    }


}