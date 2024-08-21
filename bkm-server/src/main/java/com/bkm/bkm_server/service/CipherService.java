package com.bkm.bkm_server.service;

import com.bkm.bkm_server.config.SharedKey;
import com.bkm.bkm_server.util.CipherUtilECDH;
import com.bkm.bkm_server.util.JWEUtil;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

@Service
@Slf4j
public class CipherService {
    private String embeddedOfPrivateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDmZwxydYT/xWj7CB9UZEeEqsYah2pT7c//+PBswSu1oOicxTeUjDcb2lGms3N0viAsaW1GWuWtT01FUdxVOAJDRZvhYjIR136Uo2XaRgScZMumM9+q11zJwwSMEhvvGrn679aulnRJTBfosBRDRMGUues2qCgB71FyUAqKBGUvbn/LjrEVFY7OWNImRV+4YcNm88iI+qP6oL/+GiqvaXEkHwPPkhpPGZnSqctqDU7nqw5qSorjYVkqtM4lrAhrWeKisx3v7JPXEwYl1IPY+EPiFy19tGwOd/TN+oihbBJljY/8mECu4MiD3bi/Up9PUXPUXkic+FbrXA0SofpXabTAgMBAAECggEAChBWZytkoFCmEjk5kgyjmWjmX0PuAxfSZX7cm1k75Z10APKrpOx4caqbzeGtQP31Hq3+Hl77ShWeIodyXNmRfDzYF7nU+cNACcKftkJWgOXDZ+xogt1S2kmehzW2bGVTNbE9U342Dn50n8Kc40siMdeZ0g6QhJQ8BxPIVqZ9Amp0429xZq0rdOpC0QmiK6oaYGHrfhDG1vqNJb020k0JlveeOP7NJWNdMYG/2BVKZykdoZxtNWMIgSTQ0VMEIUXkwIf0m7WjoRYxU/G9TKqVxQiIEpJSHIk+N1JM9mNcMRydaXCv7wXw6c7XSHJjsZXp8yrjFQZzxdRzLVv3xzr1IQKBgQDXurrO7pJzwyn3KmntDK+5E6PZZEuuPdAdveMxaEQLroXcTqRDJWpW0PH+TPYhyRAe544EFX4JhVzoXqR+OhRbVo3OTJwkj7Cqv9u/lHeBdVvxPx7tNQEDYSdj9Gb3PV+MNbbhfCIVgl1GvY9QK46pj+szicMO1f6xO73g9glvMwKBgQDoHPBFvCD4I0uVn7EQOudRtUwI25kGugi0dHq2fjSoTdGk1JaIy6zquITnNnnD2TRLRhBj4xUhn31psP24slRO4CGABKUt4+gQuFumK/3XDNH8cZIbiwZO8h7GkUxlSdERahDyH+R7BH2oIjtoguISyHT8WA3rqPbswc7fva1p4QKBgQClA451TwPzTKvDBkx0KKoZda51UUSaiWmx9lfcqRazoNF/zR/UxL/snHMexBvZiASuvwxgj1gTTFHe5NYKP77mhvR9gxhE1yyZz5v1lUk8W1ry1AeCBnM59Iy+5moEYIu/oi67l8oyjb9vpvwCpO7BQPb2O0BbDtF9HGeHtmtNBQKBgHGX3/qwxA3L8Cysd1HzEcvKBwj6t1w0ZRgzPO7cutZ3JxcctwMBcoF4hgpFfbfcL5x7EIBh3LCUxiKYbMMb+uiTBbIKE/Bubd7o6mlbdCHvc0CxMAjss8yk72zMJPAY/QkhuGNWOlH986T6A8r06sC4e5AXY9Cl4xohCyYyRJDhAoGBAJWnHH8VNnnNtvHszWTWINrdIdqFYoj+4H9PAUPxw/b0QamSD5h0fDcPLr8jeS4OLCaJ8zqmEp5OK//fFKcyr8Oq9SyY+ZMjc44HTQ8NLpTgjxfC4qO21byxuWt2+hseYu1C0HX6ypdzHeCfOKA2InbO/Jm6JVIpTjHCQVCAcXS6";

    private final SharedKey sharedKey;

    public CipherService(SharedKey sharedKey) {
        this.sharedKey = sharedKey;
    }

    public String sendToPublicKey(String publicKey) {
        KeyPair keyPair = CipherUtilECDH.generateKeys();
        PublicKey bkmPublicKey = keyPair.getPublic();
        PrivateKey bkmPrivateKey = keyPair.getPrivate();
        String bkmPublicKeyStr = CipherUtilECDH.encodeKey(bkmPublicKey);
        PublicKey kafatechPublicKey = CipherUtilECDH.decodePublicKey(publicKey);

        SecretKey aesKeyBKM = CipherUtilECDH.generateSecretKey();
        String aesKeyBKMStr = CipherUtilECDH.encodeKey(aesKeyBKM);
        String aesKeyEncryptWithKafatechPublicKey = CipherUtilECDH.encryptAsymmetric(aesKeyBKMStr, kafatechPublicKey);
        String bkmPublicKeyEncryptWithAESKey = CipherUtilECDH.encryptSymmetric(bkmPublicKeyStr, aesKeyBKM);
        String commonSecretKey = CipherUtilECDH.generateCommonSecretKey(bkmPrivateKey, kafatechPublicKey);
        String combined = aesKeyEncryptWithKafatechPublicKey + "." + bkmPublicKeyEncryptWithAESKey;
        sharedKey.setSharedKey(commonSecretKey);
        return combined;
    }
    //TODO BURASI CALISAN KOD ASAGIDA AYNI METHOD ILE FARKLI BIR DENEME YAPIYORUM
//    public String sendToPublicKey2(String clientPubKey) throws Exception {
//        KeyPair keyPair = CipherUtilECDH.generateKeys();
//        PublicKey bkmPublicKey = keyPair.getPublic();
//        PublicKey clientPublicKey = CipherService.convertJwkToPublicKey(clientPubKey);
//        System.out.println("CLIENT Public Key: " + CipherUtilECDH.encodeKey(clientPublicKey));
//        System.out.println("BKM Public Key: " + CipherUtilECDH.encodeKey(bkmPublicKey));
//        //ortak key elde etme
//        String commonSecretKey = CipherUtilECDH.generateCommonSecretKey(keyPair.getPrivate(), clientPublicKey);
//        System.out.println("Common Secret Key: " + commonSecretKey);
//        sharedKey.setSharedKey(commonSecretKey);
//        //ortak key ile sifrele
//        String sifrelenecekVeri = "Merhaba";
//        SecretKey secretKey = CipherUtilECDH.decodeSecretKey(commonSecretKey);
//        String encryptedData = CipherUtilECDH.encryptSymmetric(sifrelenecekVeri, secretKey);
//        System.out.println("Encrypted Data: " + encryptedData);
//        //decrypt et
//        String decryptedData = CipherUtilECDH.decryptSymmetric(encryptedData, secretKey);
//        System.out.println("Decrypted Data: " + decryptedData);
//        return CipherUtilECDH.encodeKey(bkmPublicKey);
//    }

    //    public String sendToPublicKey2(String publicKeyRequest) throws Exception {
//        KeyPair keyPair = CipherUtilECDH.generateKeys();
//        PublicKey bkmPublicKey = keyPair.getPublic();
//
//        KeyPair keyPairForRSA = CipherUtilRSA.getInstance().getKeyPair();
//        PublicKey bkmPublicKeyForRSA = keyPairForRSA.getPublic();
//        //bkm public keyi stringe cevir
//        System.out.println("BKM ECDH Public Key: " + CipherUtilECDH.encodeKey(bkmPublicKey));
//        System.out.println("BKM RSA Public Key: " + CipherUtilRSA.encodeKey(bkmPublicKeyForRSA));
//        String decodePayloadFromJWE = JWEUtil.decodePayloadFromJWEForRSA(publicKeyRequest.getEncryptedJWE(), embeddedOfPrivateKey);
//
//        System.out.println("decodePayloadFromJWE: " + decodePayloadFromJWE);
//        System.out.println("Client EC Public Key: " + CipherUtilECDH.encodeKey(CipherService.convertJwkToPublicKey(decodePayloadFromJWE)));
//
//        //TODO Burda simdi kendi server ec pub'ini karsi tarafin ec pub ile sifreleyip JWE olustur ve karsiya gonder.
//        System.out.println("client RSA pub key: " + publicKeyRequest.getRsaPubKey());
//        //JWEUtil.createJWE(CipherUtilECDH.encodeKey(bkmPublicKey),CipherUtilECDH.encodeKey(CipherService.convertJwkToPublicKey(decodePayloadFromJWE)));
//        System.out.println("ASdasd" + CipherUtilRSA.decodePublicKey(publicKeyRequest.getRsaPubKey()));
//        //return JWEUtil.createJWEForRSA(CipherUtilECDH.encodeKey(bkmPublicKey),publicKeyRequest.getRsaPubKey());
//        //return JWEUtil.createJWEForEC(CipherUtilECDH.encodeKey(bkmPublicKey),);
//        return JWEUtil.createJWEForRSA(CipherUtilECDH.encodeKey(bkmPublicKey),embeddedOfPrivateKey);
//    }
    public String sendToPublicKey2(String encryptedJWE) throws Exception {
        KeyPair keyPair = CipherUtilECDH.generateKeys();
        PublicKey serverPublicKey = keyPair.getPublic();

        PublicKey clientPublicKey = CipherService.convertJwkToPublicKey(encryptedJWE);
        System.out.println("CLIENT Public Key: " + CipherUtilECDH.encodeKey(clientPublicKey));
        System.out.println("Server Public Key: " + CipherUtilECDH.encodeKey(serverPublicKey));


        //ortak key elde etme
        String commonSecretKey = CipherUtilECDH.generateCommonSecretKey(keyPair.getPrivate(), clientPublicKey);
        System.out.println("Common Secret Key: " + commonSecretKey);
        String encData = CipherUtilECDH.encryptSymmetric("OK", CipherUtilECDH.decodeSecretKey(commonSecretKey));
        System.out.println("Encrypted Data: " + encData);
        //decrypt et
        String decryptedData = CipherUtilECDH.decryptSymmetric(encData, CipherUtilECDH.decodeSecretKey(commonSecretKey));
        System.out.println("Decrypted Data: " + decryptedData);
        sharedKey.setSharedKey(commonSecretKey);

        //ortak key ile sifrele
        String jwe = JWEUtil.generateJweWithECSecret("OK", CipherUtilECDH.encodeKey(serverPublicKey), commonSecretKey);
        log.info("Encrypted jwe: " + jwe);
        return jwe;

        /*

        //ortak key ile sifrele
        String sifrelenecekVeri = "Merhaba";
        SecretKey secretKey = CipherUtilECDH.decodeSecretKey(commonSecretKey);
        String encryptedData = CipherUtilECDH.encryptSymmetric(sifrelenecekVeri, secretKey);
        System.out.println("Encrypted Data: " + encryptedData);
        //decrypt et
        String decryptedData = CipherUtilECDH.decryptSymmetric(encryptedData, secretKey);
        System.out.println("Decrypted Data: " + decryptedData);



        KeyPair keyPairRSA = CipherUtilRSA.getInstance().getKeyPair();
        PublicKey rsaPublic = keyPairRSA.getPublic();
       return JWEUtil.createJWEForRSADENEME("OK", CipherUtilRSA.encodeKey(rsaPublic));
         */
    }


    public static PublicKey convertJwkToPublicKey(String jwkJson) throws Exception {
        // Parse the JWK JSON
        JWK jwk = JWK.parse(jwkJson);

        ECKey ecKey = (ECKey) jwk;

        if (jwk.getKeyType() != KeyType.EC) {
            throw new IllegalArgumentException("Only EC keys are supported");
        }

        return ecKey.toPublicKey();
    }

    public String decrypt(String encryptData) {
        String decryptData = CipherUtilECDH.decryptSymmetricc(encryptData, sharedKey.getSharedKey(), "gaOr3uvhZEwFeSsd".getBytes());
        String encryptDataa = "Selam kafatech. Mesajini aldim. Mesajin bu mu: " + decryptData;
        String sendEncryptData = CipherUtilECDH.encryptSymmetricc(encryptDataa, sharedKey.getSharedKey(), "gaOr3uvhZEwFeSsd".getBytes());
        // String a = decrypt("1quilwYjUdstllArKavfdg==", "F14D699136246C63B9A86D95911F4911", "gaOr3uvhZEwFeSsd".getBytes());
        System.out.println("Decrypted Data: " + decryptData);
        return sendEncryptData;
    }
}
