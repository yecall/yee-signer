package io.yeeco.yeesigner;

import java.util.HashMap;
import java.util.Map;

public class ErrorUtils {

    private static Map<Byte, String> errorMessage = new HashMap<Byte, String>() {{
        put((byte) 1, "unknown");
        put((byte) 2, "invalid mini secret key");
        put((byte) 3, "invalid secret key");
        put((byte) 4, "invalid public key");
        put((byte) 5, "invalid signature");
        put((byte) 6, "jni error");
        put((byte) 7, "invalid method");
        put((byte) 8, "invalid tx");
        put((byte) 9, "invalid json");
    }};

    public static void checkErrorCode(byte code) throws SignerException {

        if (code != 0) {
            String message = errorMessage.get(code);
            message = message != null ? message : "unknown";
            throw new SignerException(message);

        }

    }

}
