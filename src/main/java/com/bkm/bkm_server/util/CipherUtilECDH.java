package com.bkm.bkm_server.util;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

@Component
public class CipherUtilECDH {
    public static String generateCommonSecretKey(PrivateKey privateKey, PublicKey receivedPublicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(receivedPublicKey, true);
            byte[] secretKey = keyAgreement.generateSecret();
            return Base64.getEncoder().encodeToString(secretKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalStateException e) {
            throw new RuntimeException("Error generating common secret key", e);
        }
    }


    public static KeyPair generateKeys() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(256);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generating key pair", e);
        }
    }

    public static ECPublicKey decodeECPublicKey(String base64PublicKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return (ECPublicKey) keyFactory.generatePublic(keySpec);
    }
    public static String encodeKey(Key key) {
        try {
            byte[] keyBytes = key.getEncoded();
            return Base64.getEncoder().encodeToString(keyBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error encoding key", e);
        }
    }
    public static PrivateKey decodePrivateKey(String keyStr)  {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePrivate(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error decoding public key", e);
        }
    }
    public static PublicKey decodePublicKey(String keyStr)  {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error decoding public key", e);
        }
    }
    public static String encryptSymmetric(String data, String key, byte[] iv) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(key);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(data.getBytes());
            var encryptedData = Base64.getEncoder().encode(encryptedBytes);
            return new String(encryptedData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String encryptSymmetric(String content, SecretKey secretKey)  {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] cipherContent = cipher.doFinal(content.getBytes());
            return Base64.getEncoder().encodeToString(cipherContent);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Error encrypting symmetric content", e);
        }
    }
    public static String getFirst32Bytes(String key) {
        byte[] keyBytes = key.getBytes();
        byte[] key32Bytes = Arrays.copyOf(keyBytes, 32); // İlk 32 byte'ı al
        return new String(key32Bytes);
    }

    public static String decryptSymmetric(String encryptedData, String key, byte[] iv)  {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(key);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        }catch (Exception e){
            throw new RuntimeException("Error decrypting symmetric content", e);
        }
    }
    public static String decryptSymmetriccDENEME(byte[] encryptedData, String key, byte[] iv)  {
        key = getFirst32Bytes(key);
        try {
            System.out.println("Key: " + key);
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            //byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = cipher.doFinal(encryptedData);
            return new String(decryptedBytes);
        }catch (Exception e){
            throw new RuntimeException("Error decrypting symmetric content", e);
        }
    }

    public static String decryptSymmetric(String cipherContent, SecretKey secretKey)  {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] cipherContentBytes = Base64.getDecoder().decode(cipherContent);
            byte[] decryptedContent = cipher.doFinal(cipherContentBytes);
            return new String(decryptedContent);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Error decrypting symmetric content", e);
        }
    }

    public static String encryptAsymmetric(String content, Key pubKey)  {
        try {
            Cipher cipher = Cipher.getInstance("ECIES");
            IESParameterSpec iesParams = new IESParameterSpec(null, null, 256);
            cipher.init(Cipher.ENCRYPT_MODE, pubKey, iesParams);
            byte[] cipherContent = cipher.doFinal(content.getBytes());
            return Base64.getEncoder().encodeToString(cipherContent);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Error encrypting asymmetric content", e);
        }
    }

    public static String decryptAsymmetric(String cipherContent, Key privKey)  {
        try {
            Cipher cipher = Cipher.getInstance("ECIES");
            IESParameterSpec iesParams = new IESParameterSpec(null, null, 256);
            cipher.init(Cipher.DECRYPT_MODE, privKey, iesParams);
            byte[] cipherContentBytes = Base64.getDecoder().decode(cipherContent);
            byte[] decryptedContent = cipher.doFinal(cipherContentBytes);
            return new String(decryptedContent);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Error decrypting asymmetric content", e);
        }
    }

    public static SecretKey generateSecretKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generate secret key", e);
        }
    }
    public static SecretKey decodeSecretKey(String keyStr) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);
            return new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Error decoding secret key", e);
        }
    }

}

