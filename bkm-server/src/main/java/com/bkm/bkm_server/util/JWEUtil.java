package com.bkm.bkm_server.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class JWEUtil {

    public static String createJWEForRSA(String payloadData, String base64PublicKey) throws Exception {
        //KeyPair keyPair = RSAUtilForJWE.generateRSAKeyPair();
        //RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPublicKey publicKey = (RSAPublicKey) CipherUtilRSA.decodePublicKey(base64PublicKey);
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);
        Payload payload = new Payload(payloadData);
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new RSAEncrypter(publicKey));
        return jweObject.serialize();
    }


    public static String generateJweWithECSecret(String payloadData, String serverPublicKey, String secret) throws Exception {
        // Create the JWE header
//        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
//                .customParam("myPubKey", serverPublicKey)
//                .build();
        ECKey jwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) CipherUtilECDH.decodePublicKey(serverPublicKey))
                .keyUse(KeyUse.ENCRYPTION)
                .build();
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                .customParam("myPubKey", jwk.toPublicJWK().toJSONString())
                .build();

        // Create the JWE object with the header and payload
        JWEObject jweObject = new JWEObject(header, new Payload(payloadData));

        // Encrypt the payload using the secret key
        jweObject.encrypt(new DirectEncrypter(CipherUtilECDH.decodeSecretKey(secret)));

        // Serialize the JWE object to a compact string
        return jweObject.serialize();
    }



    public static String createJWEForRSADENEME(String payloadData, String base64PublicKey) throws Exception {
        //KeyPair keyPair = RSAUtilForJWE.generateRSAKeyPair();
        //RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPublicKey publicKey = (RSAPublicKey) CipherUtilRSA.decodePublicKey(base64PublicKey);
        KeyPair keyPair = CipherUtilECDH.generateKeys();
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        String myPublicKey = CipherUtilECDH.encodeKey(ecPublicKey);

        ECKey jwk = new ECKey.Builder(Curve.P_256, ecPublicKey)
                .keyUse(KeyUse.ENCRYPTION)
                .build();
        System.out.println("Serverin olusturdugu JWK: " + jwk.toJSONString());

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                .customParam("myPubKey", myPublicKey)
                .build();

        Payload payload = new Payload(payloadData);
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new RSAEncrypter(publicKey));
        return jweObject.serialize();
    }

    public static String createJWEForEC(String payloadData, String ecPublicKey) throws Exception {
        JWEHeader header = new JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM);
        Payload payload = new Payload(payloadData);
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new ECDHEncrypter((ECPublicKey) CipherUtilECDH.decodePublicKey(ecPublicKey)));
        return jweObject.serialize();
    }

    public static String createJWEForDENEME(String payloadData, String ecPublicKey) throws Exception {
        KeyPair keyPair = CipherUtilECDH.generateKeys();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        String myPublicKey = CipherUtilECDH.encodeKey(publicKey);

        ECKey jwk = new ECKey.Builder(Curve.P_256, publicKey)
                .keyUse(KeyUse.ENCRYPTION)
                .build();

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM)
                .customParam("myPubKey", jwk.toPublicJWK().toJSONString())
                .build();

        Payload payload = new Payload(payloadData);
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new ECDHEncrypter((ECPublicKey) CipherUtilECDH.decodePublicKey(ecPublicKey)));
        return jweObject.serialize();
    }

    public static String createJWEForParametreliEC(String payloadData, String ecPublicKey) throws Exception {
        KeyPair keyPair = CipherUtilECDH.generateKeys();
        PublicKey publicKey = keyPair.getPublic();
        String myPublicKey = CipherUtilECDH.encodeKey(publicKey);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM)
                .customParam("myPubKey", myPublicKey)
                .build();

        Payload payload = new Payload(payloadData);
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new ECDHEncrypter((ECPublicKey) CipherUtilECDH.decodePublicKey(ecPublicKey)));
        return jweObject.serialize();
    }

    public static String decodePayloadFromJWEForRSA(String jweSwift, String embeddedOfPrivateKey) throws Exception {
        JWEObject jweObjectToDecrypt = JWEObject.parse(jweSwift);
        jweObjectToDecrypt.decrypt(new RSADecrypter(CipherUtilRSA.decodePrivateKey(embeddedOfPrivateKey)));
        return jweObjectToDecrypt.getPayload().toString();
    }

    public static String decodePayloadFromJWEForEC(String jweSwift, PrivateKey embeddedOfPrivateKey) throws Exception {
        JWEObject jweObjectToDecrypt = JWEObject.parse(jweSwift);
        jweObjectToDecrypt.decrypt(new ECDHDecrypter((ECPrivateKey) embeddedOfPrivateKey));
        return jweObjectToDecrypt.getPayload().toString();
    }

}
