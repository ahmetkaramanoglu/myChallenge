package com.bkm.bkm_server.util;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class CipherUtilRSA {
    //Util sinifinin tek bir örneğini oluşturmak daha mantikli geldi. Cunku bu sinifin farkli farkli nesnelerinin olmasi mantiksiz geldi. Hep ayni isleri yapiyor.
    private static CipherUtilRSA instance;
    //KeyPairGenerator, anahtar çiftleri oluşturmak için kullanılan bir sınıftır.
    //KeyPairGenerator sınıfı, şifreleme algoritmalarına dayalı anahtar çiftleri oluşturmak için kullanılan bir Java sınıfıdır.
    // Genellikle, bir şifreleme algoritması (örneğin RSA, DSA, EC) belirli parametrelerle başlatılır ve ardından genKeyPair() metodu kullanılarak anahtar çiftleri oluşturulur.
    private static KeyPairGenerator keyPairGenerator = null;

    private CipherUtilRSA() {
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    public static CipherUtilRSA getInstance() {
        if (instance == null) {
            synchronized (CipherUtilRSA.class) {
                if (instance == null) {
                    instance = new CipherUtilRSA();
                }
            }
        }
        return instance;
    }

    //KeyPairGenerator nesnesi kullanarak bir anahtar çifti (public ve private anahtar) oluşturur

    public KeyPair getKeyPair() {
        return keyPairGenerator.genKeyPair();
    }
    public SecretKey generateSecretKey() {
        try {
            // AES için bir KeyGenerator oluştur
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // Key boyutu (AES için 256 bit önerilir)
            return keyGen.generateKey(); // SecretKey oluştur ve geri döndür
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate AES secret key", e);
        }
    }
    /*
     * byte[] contentBytes = content.getBytes(); Verilen metni (content) bayt dizisine çevirir.
     * byte[] cipherContent = cipher.doFinal(contentBytes); Metni (bayt dizisini) RSA algoritmasını kullanarak şifreler ve şifrelenmiş bayt dizisini döner.
     * String encoded = Base64.getEncoder().encodeToString(cipherContent); Şifrelenmiş bayt dizisini Base64 formatında kodlayarak bir String döner
     * */
    public static String encryptSymmetric(String content, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] cipherContent = cipher.doFinal(content.getBytes());
        return Base64.getEncoder().encodeToString(cipherContent);
    }
    public PublicKey generatePublicKey() {
        return getKeyPair().getPublic();
    }

    public static String decryptSymmetric(String cipherContent, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] cipherContentBytes = Base64.getDecoder().decode(cipherContent);
        byte[] decryptedContent = cipher.doFinal(cipherContentBytes);
        return new String(decryptedContent);
    }

    public static String encryptAsymmetric(String content, Key pubKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] cipherContent = cipher.doFinal(content.getBytes());
        return Base64.getEncoder().encodeToString(cipherContent);
    }
    public static String encryptAESKeyWithRSA(String aesKey, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(aesKey.getBytes());
        return Base64.getEncoder().encodeToString(encryptedKey);
    }


    public static String decryptAsymmetric(String cipherContent, Key privKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] cipherContentBytes = Base64.getDecoder().decode(cipherContent);
        byte[] decryptedContent = cipher.doFinal(cipherContentBytes);
        return new String(decryptedContent);
    }
    //Bu metod, verilen bir anahtarı Base64 formatında kodlar. Bu genellikle, anahtarı bir dosyada veya veritabanında güvenli bir şekilde saklamak için kullanılır.
    public static String encodeKey(Key key) {
        byte[] keyBytes = key.getEncoded();
        String encodedKeyStr = Base64.getEncoder().encodeToString(keyBytes);
        return encodedKeyStr;
    }

    public static PublicKey decodePublicKey(String keyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(keyStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(spec);
        return key;
    }

    public static PrivateKey decodePrivateKey(String keyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(keyStr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey key = keyFactory.generatePrivate(keySpec);
        return key;
    }


}