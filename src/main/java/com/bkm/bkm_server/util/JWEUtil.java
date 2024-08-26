package com.bkm.bkm_server.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import java.security.interfaces.ECPublicKey;

public class JWEUtil {

    public static String generateJweWithECSecret(String payloadDataJSON, String serverPublicKey, String secret) throws Exception {
        ECKey jwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) CipherUtilECDH.decodePublicKey(serverPublicKey))
                .keyUse(KeyUse.ENCRYPTION)
                .build();

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                .customParam("myPubKey", jwk.toPublicJWK().toJSONString())
                .build();

        // Create the JWE object with the header and payload
        JWEObject jweObject = new JWEObject(header, new Payload(payloadDataJSON));

        // Encrypt the payload using the secret key
        jweObject.encrypt(new DirectEncrypter(CipherUtilECDH.decodeSecretKey(secret)));

        // Serialize the JWE object to a compact string
        return jweObject.serialize();
    }

    public static String decodePayloadFromJWEForRSA(String jweSwift, String embeddedOfPrivateKey) throws Exception {
        JWEObject jweObjectToDecrypt = JWEObject.parse(jweSwift);
        jweObjectToDecrypt.decrypt(new RSADecrypter(CipherUtilRSA.decodePrivateKey(embeddedOfPrivateKey)));
        return jweObjectToDecrypt.getPayload().toString();
    }

}
