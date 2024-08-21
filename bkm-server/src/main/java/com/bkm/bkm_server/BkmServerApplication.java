package com.bkm.bkm_server;

import com.bkm.bkm_server.model.Card;
import com.bkm.bkm_server.repository.CardRepository;
import com.bkm.bkm_server.repository.UserRepository;
import com.bkm.bkm_server.util.CipherUtilECDH;
import com.bkm.bkm_server.util.CipherUtilRSA;
import com.bkm.bkm_server.util.JWEUtil;
import com.bkm.bkm_server.util.RSAUtilForJWE;
import lombok.AllArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;


@SpringBootApplication(exclude = { SecurityAutoConfiguration.class })
@AllArgsConstructor
public class BkmServerApplication implements CommandLineRunner {
	private final CardRepository cardRepository;
	private final UserRepository userRepository;

    public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		System.out.println("BkmServerApplication main");
		SpringApplication.run(BkmServerApplication.class, args);
	}

	public static void createDenemeJWE() throws Exception {
		KeyPair keyPair = CipherUtilECDH.generateKeys();
		PublicKey bkmPublicKey = keyPair.getPublic();
		KeyPair keyPairRSA = CipherUtilRSA.getInstance().getKeyPair();
		PublicKey rsaPublic = keyPairRSA.getPublic();

		String ecJWKToJWE = JWEUtil.createJWEForDENEME("selam kafatech", CipherUtilECDH.encodeKey(bkmPublicKey));
		String baskaJWE = JWEUtil.createJWEForEC("selam kafatech", CipherUtilECDH.encodeKey(bkmPublicKey));
		String base64ParamKey = JWEUtil.createJWEForParametreliEC("selam kafatech", CipherUtilECDH.encodeKey(bkmPublicKey));
		String rsaDENEME = JWEUtil.createJWEForRSA("selam kafatech", CipherUtilRSA.encodeKey(rsaPublic));
		String rsaDENEME2 = JWEUtil.createJWEForRSADENEME("selam kafatech", CipherUtilRSA.encodeKey(rsaPublic));

		System.out.println("EC JWK OLUSTURDUGUM JWE: " + ecJWKToJWE);
		System.out.println("RSA OLUSTURDUGUM JWE: " + rsaDENEME);
		System.out.println("RSA + EC OLUSTURDUGUM JWE: " + rsaDENEME2);
		System.out.println("BASKA JWE: " + baskaJWE);
		System.out.println("base64ParamKey JWE: " + base64ParamKey);
		String payloadDenemeJWE = JWEUtil.decodePayloadFromJWEForEC(baskaJWE, keyPair.getPrivate());
		System.out.println("Payload: " + payloadDenemeJWE);

	}

	@Override
	public void run(String... args) throws Exception {
		userRepository.deleteAll();
		Card card = new Card(1L, "12/23", "Ahmet");
		Card card2 = new Card(2L, "12/23", "Mehmet");
		Card card3 = new Card(3L, "12/23", "Omer");
		cardRepository.saveAll(java.util.List.of(card, card2, card3));

		KeyPair keyPair = RSAUtilForJWE.generateRSAKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		String embeddedOfPrivateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDmZwxydYT/xWj7CB9UZEeEqsYah2pT7c//+PBswSu1oOicxTeUjDcb2lGms3N0viAsaW1GWuWtT01FUdxVOAJDRZvhYjIR136Uo2XaRgScZMumM9+q11zJwwSMEhvvGrn679aulnRJTBfosBRDRMGUues2qCgB71FyUAqKBGUvbn/LjrEVFY7OWNImRV+4YcNm88iI+qP6oL/+GiqvaXEkHwPPkhpPGZnSqctqDU7nqw5qSorjYVkqtM4lrAhrWeKisx3v7JPXEwYl1IPY+EPiFy19tGwOd/TN+oihbBJljY/8mECu4MiD3bi/Up9PUXPUXkic+FbrXA0SofpXabTAgMBAAECggEAChBWZytkoFCmEjk5kgyjmWjmX0PuAxfSZX7cm1k75Z10APKrpOx4caqbzeGtQP31Hq3+Hl77ShWeIodyXNmRfDzYF7nU+cNACcKftkJWgOXDZ+xogt1S2kmehzW2bGVTNbE9U342Dn50n8Kc40siMdeZ0g6QhJQ8BxPIVqZ9Amp0429xZq0rdOpC0QmiK6oaYGHrfhDG1vqNJb020k0JlveeOP7NJWNdMYG/2BVKZykdoZxtNWMIgSTQ0VMEIUXkwIf0m7WjoRYxU/G9TKqVxQiIEpJSHIk+N1JM9mNcMRydaXCv7wXw6c7XSHJjsZXp8yrjFQZzxdRzLVv3xzr1IQKBgQDXurrO7pJzwyn3KmntDK+5E6PZZEuuPdAdveMxaEQLroXcTqRDJWpW0PH+TPYhyRAe544EFX4JhVzoXqR+OhRbVo3OTJwkj7Cqv9u/lHeBdVvxPx7tNQEDYSdj9Gb3PV+MNbbhfCIVgl1GvY9QK46pj+szicMO1f6xO73g9glvMwKBgQDoHPBFvCD4I0uVn7EQOudRtUwI25kGugi0dHq2fjSoTdGk1JaIy6zquITnNnnD2TRLRhBj4xUhn31psP24slRO4CGABKUt4+gQuFumK/3XDNH8cZIbiwZO8h7GkUxlSdERahDyH+R7BH2oIjtoguISyHT8WA3rqPbswc7fva1p4QKBgQClA451TwPzTKvDBkx0KKoZda51UUSaiWmx9lfcqRazoNF/zR/UxL/snHMexBvZiASuvwxgj1gTTFHe5NYKP77mhvR9gxhE1yyZz5v1lUk8W1ry1AeCBnM59Iy+5moEYIu/oi67l8oyjb9vpvwCpO7BQPb2O0BbDtF9HGeHtmtNBQKBgHGX3/qwxA3L8Cysd1HzEcvKBwj6t1w0ZRgzPO7cutZ3JxcctwMBcoF4hgpFfbfcL5x7EIBh3LCUxiKYbMMb+uiTBbIKE/Bubd7o6mlbdCHvc0CxMAjss8yk72zMJPAY/QkhuGNWOlH986T6A8r06sC4e5AXY9Cl4xohCyYyRJDhAoGBAJWnHH8VNnnNtvHszWTWINrdIdqFYoj+4H9PAUPxw/b0QamSD5h0fDcPLr8jeS4OLCaJ8zqmEp5OK//fFKcyr8Oq9SyY+ZMjc44HTQ8NLpTgjxfC4qO21byxuWt2+hseYu1C0HX6ypdzHeCfOKA2InbO/Jm6JVIpTjHCQVCAcXS6";
	createDenemeJWE();
		//		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);
//
//		Payload payload = new Payload("Hello, world!");
//		// JWE nesnesini oluşturun
//		JWEObject jweObject = new JWEObject(header, payload);
//
//		// Şifreleme
//		jweObject.encrypt(new RSAEncrypter(publicKey));

		// JWE'yi dizgeye dönüştürün
		//String jweString = jweObject.serialize();
		//String javaJWE = JWEUtil.createJWE("Selam.");
		//System.out.println("Java JWE: " + javaJWE);
		String jweSwift = "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBMV81In0.czj6MUAxqYnn7Oglm1lGhdovx_oYVtPUx8HpnD2zEp2oif8LCMxISU-WYJr5QT2Qq19xgCsUa1ifwoz--R9p5oNNGsSOfQVLmPEE-n1nsMa9FaZlk_zSo3seGKfhTgmvFnm_3GN8nr6-8fe9QPWrugDiwrx4zy50VZH_Wv5_YY7mc4seX6LesKgHFpbWf4BJ0xnQhT0JJQzAOAnThMacWbCWW7tTBB-VUxRz3GNNUxwukb5sbyiCU3TIKJhP7YqkGak8NRAATn7llhCjxZzWQ2AIWAVEmoQMjcnllTKjHurokXBLpd99ictebxeo-xs-tF00fgQUCPsAhTiUldWUtA.uZw5hCUYHYA9ZmDq5I7v5A.iKFjuiuZsO-rRYWFPZO2SVEZ-0wPAuTF_x2BElS8ggY.wuPQm0yG7JeszGC8IJIg9UK-0oO5WdJrMWucY2R6IYo";

		// JWE'yi çözme
//		JWEObject jweObjectToDecrypt = JWEObject.parse(jweSwift);
//		jweObjectToDecrypt.decrypt(new RSADecrypter(CipherUtilRSA.decodePrivateKey(embeddedOfPrivateKey)));

		// Çözülen yükü alın
		String decryptMessage = JWEUtil.decodePayloadFromJWEForRSA(jweSwift, embeddedOfPrivateKey);
		//String decryptedMessage = jweObjectToDecrypt.getPayload().toString();
		System.out.println("Decrypted Message: " + decryptMessage);


		//String a = decrypt("1quilwYjUdstllArKavfdg==", "F14D699136246C63B9A86D95911F4911", "gaOr3uvhZEwFeSsd".getBytes());

	}
//
//

	//IV ASLA AMA ASLA BASE64 DECODE ILE DECODE EDILMEYECEK. DIREKT OLARAK GETBYTES OLARAK VERECEKSIN.
	public static String decrypt(String encryptedData, String key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
			SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
			byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
			byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
			return new String(decryptedBytes);
	}

	// AES şifre çözme metodu
	public static String decryptAES(String encryptedData, String key, String iv) throws Exception {
		// Base64 ile şifreli veriyi ve IV'yi decode et
		byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
		byte[] ivBytes = Base64.getDecoder().decode(iv);

		if (ivBytes.length != 16) {
			byte[] fullIvBytes = new byte[16];
			System.arraycopy(ivBytes, 0, fullIvBytes, 0, ivBytes.length);
			// Kalan byte'ları sıfırla
			Arrays.fill(fullIvBytes, ivBytes.length, fullIvBytes.length, (byte) 0);
			ivBytes = fullIvBytes;
		}

		ivBytes = new byte[16];

		// SecretKeySpec ve IvParameterSpec nesnelerini oluştur
		SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
		IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);

		// Cipher nesnesini oluştur ve başlat
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

		// Şifreli veriyi çöz
		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

		// Çözülmüş veriyi String'e dönüştür
		return new String(decryptedBytes, StandardCharsets.UTF_8);
	}


	public static String toPEMFormat(PublicKey publicKey) throws Exception {
		// Public key'i DER formatında al
		byte[] encoded = publicKey.getEncoded();

		// DER formatını Base64 ile kodla
		String base64Encoded = Base64.getEncoder().encodeToString(encoded);

		// PEM formatına dönüştür, satır uzunluğunu 64 karaktere ayarla
		StringBuilder pemBuilder = new StringBuilder();
		pemBuilder.append("-----BEGIN PUBLIC KEY-----\n");

		// 64 karakterlik satırlara böl
		int length = base64Encoded.length();
		for (int i = 0; i < length; i += 64) {
			int end = Math.min(length, i + 64);
			pemBuilder.append(base64Encoded, i, end).append("\n");
		}

		pemBuilder.append("-----END PUBLIC KEY-----");
		return pemBuilder.toString();
	}

	public static PublicKey getPublicKeyFromPEM2(String pem) throws Exception {
		// PEM başlıkları ve alt başlıkları kaldırma
		String cleanedPem = pem.replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "")
				.replaceAll("\\s", "");

		//MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZ37y8UU11QPa9wX7lzFIlTMyLeWp7XgFYmAiFv3RP8q4Ak5yg8OYZEXon0l6zt7ICaR23n5T34G+YlYr+JWkpQ==
		//MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBCdavlEjOqofBWzbhudffySdzOUuopwrASi8kzQRdi15Im46B4RMa3QTSoFsx96N0cPMp+iw2P9RhEKGjBQxRb0=

		// Base64 çözme
		byte[] decoded = Base64.getDecoder().decode(cleanedPem);

		// PublicKey nesnesini oluşturma
		KeyFactory keyFactory = KeyFactory.getInstance("EC"); // Eliptik eğri algoritması için "EC"
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
		return keyFactory.generatePublic(keySpec);
	}




	public static PublicKey getPublicKeyFromPEM(String der) throws Exception {

		// Base64 çözme
		byte[] decoded = Base64.getDecoder().decode(der);

		// PublicKey nesnesini oluşturma
		KeyFactory keyFactory = KeyFactory.getInstance("EC"); // Eliptik eğri algoritması için "EC"
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
		return keyFactory.generatePublic(keySpec);
	}
}
