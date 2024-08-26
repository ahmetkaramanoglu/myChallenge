package com.bkm.bkm_server;

import com.bkm.bkm_server.model.Card;
import com.bkm.bkm_server.repository.CardRepository;
import com.bkm.bkm_server.repository.UserRepository;
import com.bkm.bkm_server.util.CipherUtilECDH;
import com.bkm.bkm_server.util.CipherUtilRSA;
import com.bkm.bkm_server.util.JWEUtil;
import com.bkm.bkm_server.util.RSAUtilForJWE;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.util.Base64URL;
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
		SpringApplication.run(BkmServerApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		userRepository.deleteAll();
		Card card = new Card(1L, "12/23", "Ahmet");
		Card card2 = new Card(2L, "12/23", "Mehmet");
		Card card3 = new Card(3L, "12/23", "Omer");
		cardRepository.saveAll(java.util.List.of(card, card2, card3));


	}

}
