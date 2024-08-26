package com.bkm.bkm_server.util;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class CipherUtilDH {
    //singleton yap. biraz gozden gecir daha duzgun bir kod yazilabilir.

    public static String generateCommonSecretKey(PrivateKey privateKey, PublicKey receivedPublicKey) {
        try {
            final KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(receivedPublicKey, true);
            byte [] secretKey = keyAgreement.generateSecret();

            return Base64.getEncoder().encodeToString(secretKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    //Burda anahtar cifti elde ediyoruz. Diffie Hellman algoritmasini verdigimiz icin bu algoritma ile keypair olusturuyor.
    public static KeyPair generateKeys() {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public static String encodeKey(Key key) {
        byte[] keyBytes = key.getEncoded();
        String encodedKeyStr = Base64.getEncoder().encodeToString(keyBytes);
        return encodedKeyStr;
    }
    public static PublicKey decodePublicKey(String keyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(keyStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
        PublicKey key = keyFactory.generatePublic(spec);
        return key;
    }
    public static String encryptSymmetric(String content, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] cipherContent = cipher.doFinal(content.getBytes());
        return Base64.getEncoder().encodeToString(cipherContent);
    }
    public static String decryptSymmetric(String cipherContent, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] cipherContentBytes = Base64.getDecoder().decode(cipherContent);
        byte[] decryptedContent = cipher.doFinal(cipherContentBytes);
        return new String(decryptedContent);
    }
    public static SecretKey decodeSecretKey(String keyStr) {
        byte[] keyBytes = Base64.getDecoder().decode(keyStr); //Base64 formatinda kodlanmis key'i byte dizisine cevirir.
        //burda parametreye direkt olarak keystr.getbytes verilmesi olmuyor.
        return new SecretKeySpec(keyBytes,0,keyBytes.length,"AES");
    }
    public static SecretKey deriveAESKey(byte[] sharedSecret) throws Exception {
        // SHA-256 hash fonksiyonu kullanarak anahtar türetme
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha256.digest(sharedSecret);
        System.out.println("Key bytes string: " + keyBytes.toString());
        // İlk 32 baytı (AES-256 için) alın
        keyBytes = Arrays.copyOf(keyBytes, 32); // AES-256 için

        // AES anahtarını oluştur
        return new SecretKeySpec(keyBytes, "AES");
    }

}
