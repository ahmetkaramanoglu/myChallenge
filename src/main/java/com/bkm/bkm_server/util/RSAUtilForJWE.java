package com.bkm.bkm_server.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class RSAUtilForJWE {
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Anahtar uzunluğunu belirleyin
        return keyPairGenerator.generateKeyPair();
    }


}
