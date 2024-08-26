package com.bkm.bkm_server.service;

import com.bkm.bkm_server.config.SharedKey;
import com.bkm.bkm_server.request.PayloadRequest;
import com.bkm.bkm_server.request.SmsRequest;
import com.bkm.bkm_server.request.UserLoginRequest;
import com.bkm.bkm_server.response.PayloadResponse;
import com.bkm.bkm_server.util.CipherUtilECDH;
import com.bkm.bkm_server.util.JWEUtil;
import com.bkm.bkm_server.util.JsonUtil;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class CipherService {
    private String embeddedOfPrivateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDmZwxydYT/xWj7CB9UZEeEqsYah2pT7c//+PBswSu1oOicxTeUjDcb2lGms3N0viAsaW1GWuWtT01FUdxVOAJDRZvhYjIR136Uo2XaRgScZMumM9+q11zJwwSMEhvvGrn679aulnRJTBfosBRDRMGUues2qCgB71FyUAqKBGUvbn/LjrEVFY7OWNImRV+4YcNm88iI+qP6oL/+GiqvaXEkHwPPkhpPGZnSqctqDU7nqw5qSorjYVkqtM4lrAhrWeKisx3v7JPXEwYl1IPY+EPiFy19tGwOd/TN+oihbBJljY/8mECu4MiD3bi/Up9PUXPUXkic+FbrXA0SofpXabTAgMBAAECggEAChBWZytkoFCmEjk5kgyjmWjmX0PuAxfSZX7cm1k75Z10APKrpOx4caqbzeGtQP31Hq3+Hl77ShWeIodyXNmRfDzYF7nU+cNACcKftkJWgOXDZ+xogt1S2kmehzW2bGVTNbE9U342Dn50n8Kc40siMdeZ0g6QhJQ8BxPIVqZ9Amp0429xZq0rdOpC0QmiK6oaYGHrfhDG1vqNJb020k0JlveeOP7NJWNdMYG/2BVKZykdoZxtNWMIgSTQ0VMEIUXkwIf0m7WjoRYxU/G9TKqVxQiIEpJSHIk+N1JM9mNcMRydaXCv7wXw6c7XSHJjsZXp8yrjFQZzxdRzLVv3xzr1IQKBgQDXurrO7pJzwyn3KmntDK+5E6PZZEuuPdAdveMxaEQLroXcTqRDJWpW0PH+TPYhyRAe544EFX4JhVzoXqR+OhRbVo3OTJwkj7Cqv9u/lHeBdVvxPx7tNQEDYSdj9Gb3PV+MNbbhfCIVgl1GvY9QK46pj+szicMO1f6xO73g9glvMwKBgQDoHPBFvCD4I0uVn7EQOudRtUwI25kGugi0dHq2fjSoTdGk1JaIy6zquITnNnnD2TRLRhBj4xUhn31psP24slRO4CGABKUt4+gQuFumK/3XDNH8cZIbiwZO8h7GkUxlSdERahDyH+R7BH2oIjtoguISyHT8WA3rqPbswc7fva1p4QKBgQClA451TwPzTKvDBkx0KKoZda51UUSaiWmx9lfcqRazoNF/zR/UxL/snHMexBvZiASuvwxgj1gTTFHe5NYKP77mhvR9gxhE1yyZz5v1lUk8W1ry1AeCBnM59Iy+5moEYIu/oi67l8oyjb9vpvwCpO7BQPb2O0BbDtF9HGeHtmtNBQKBgHGX3/qwxA3L8Cysd1HzEcvKBwj6t1w0ZRgzPO7cutZ3JxcctwMBcoF4hgpFfbfcL5x7EIBh3LCUxiKYbMMb+uiTBbIKE/Bubd7o6mlbdCHvc0CxMAjss8yk72zMJPAY/QkhuGNWOlH986T6A8r06sC4e5AXY9Cl4xohCyYyRJDhAoGBAJWnHH8VNnnNtvHszWTWINrdIdqFYoj+4H9PAUPxw/b0QamSD5h0fDcPLr8jeS4OLCaJ8zqmEp5OK//fFKcyr8Oq9SyY+ZMjc44HTQ8NLpTgjxfC4qO21byxuWt2+hseYu1C0HX6ypdzHeCfOKA2InbO/Jm6JVIpTjHCQVCAcXS6";

    private String sms = "123456";
    private Integer [] smsProtocol;
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

    public String get32CharacterString(String base64String, List<Integer> indexes) {
        String result = indexes.stream()
                .filter(index -> index >= 0 && index < base64String.length())
                .map(index -> base64String.charAt(index))
                .map(String::valueOf)
                .collect(Collectors.joining());
        return result.toString();
    }
    public String sendToPublicKeyWithJWE(String jweOfSwift) throws Exception {
        KeyPair keyPair = CipherUtilECDH.generateKeys();
        PublicKey serverPublicKey = keyPair.getPublic();
        String payloadRequest = JWEUtil.decodePayloadFromJWEForRSA(jweOfSwift, embeddedOfPrivateKey);
        PayloadRequest payloadRequest1 = JsonUtil.stringToJson(payloadRequest, PayloadRequest.class);
        PublicKey clientPublicKey = CipherService.convertJwkToPublicKey(payloadRequest1.getESDKPUB());

        String secKeyRandom32String = get32CharacterString(CipherUtilECDH.generateCommonSecretKey(keyPair.getPrivate(), clientPublicKey),
                Arrays.stream(payloadRequest1.getSecretProtocol()).boxed().collect(Collectors.toList()));

        String base64RandomSecKey = Base64.getEncoder().encodeToString(secKeyRandom32String.getBytes());
        System.out.println("Base64 Random Secret Key: " + base64RandomSecKey);
        sharedKey.setSharedKey(base64RandomSecKey);


        List<Integer> randomList = generateShuffledListInteger();
        this.smsProtocol = randomList.toArray(new Integer[0]);

        //listeyi sout ile don
        System.out.println("Random List: " + randomList);
        String payloadResponseDataWithJSON = JsonUtil.jsonToString(
                new PayloadResponse(payloadRequest1.getClientChallengeId(),
                        UUID.randomUUID().toString(),
                        smsProtocol));
        String jwe = JWEUtil.generateJweWithECSecret(payloadResponseDataWithJSON,
                CipherUtilECDH.encodeKey(serverPublicKey),
                base64RandomSecKey);

        log.info("Encrypted jwe: " + jwe);
        return jwe;
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
        String decryptData = CipherUtilECDH.decryptSymmetric(encryptData, sharedKey.getSharedKey(), "gaOr3uvhZEwFeSsd".getBytes());
        String encryptDataa = "Selam kafatech. Mesajini aldim. Mesajin bu mu: " + decryptData;
        String sendEncryptData = CipherUtilECDH.encryptSymmetric(encryptDataa, sharedKey.getSharedKey(), "gaOr3uvhZEwFeSsd".getBytes());
        System.out.println("Decrypted Data: " + decryptData);
        return sendEncryptData;
    }
    public String decryptLoginRequest(UserLoginRequest userLoginRequest) {
        String decryptUsername = CipherUtilECDH.decryptSymmetric(userLoginRequest.getUsername(),
                sharedKey.getSharedKey(),
                "gaOr3uvhZEwFeSsd".getBytes());

        String decryptPassword = CipherUtilECDH.decryptSymmetric(userLoginRequest.getPassword(),
                sharedKey.getSharedKey(),
                "gaOr3uvhZEwFeSsd".getBytes());

        System.out.println("Decrypted Username: " + decryptUsername);
        System.out.println("Decrypted Password: " + decryptPassword);

        String sendEncryptData = CipherUtilECDH.encryptSymmetric("username ve password cozuldu.", sharedKey.getSharedKey(), "gaOr3uvhZEwFeSsd".getBytes());
        return sendEncryptData;
    }

    public String decryptSmsRequest(SmsRequest request) {
        String decryptSms = CipherUtilECDH.decryptSymmetric(request.getReceivedSms(),
                sharedKey.getSharedKey(),
                "gaOr3uvhZEwFeSsd".getBytes());
        System.out.println("Decrypted SMS: " + decryptSms);

        if(decryptSms.equals(sms)){
            Integer [] smsArray = smsStringToIntegerArray(decryptSms);
            System.out.println("SMS Array: " + Arrays.toString(smsArray));
            Integer [] combinedArray = Arrays.copyOf(smsProtocol, smsArray.length + smsProtocol.length);
            System.arraycopy(smsArray, 0, combinedArray, smsProtocol.length, smsArray.length);
            String secKeyRandomNew32Str = Base64.getEncoder().encodeToString(get32CharacterString(sharedKey.getSharedKey(), List.of(combinedArray)).getBytes());
            sharedKey.setSharedKey(secKeyRandomNew32Str);
            System.out.println("Base64 Random SMS New Secret Key: " + secKeyRandomNew32Str);
            return CipherUtilECDH.encryptSymmetric("SMS dogrulandi.", sharedKey.getSharedKey(), "gaOr3uvhZEwFeSsd".getBytes());
        }else {
            return "Dogrulama basarisiz.";
        }
    }

    public static Integer [] smsStringToIntegerArray(String sms) {
        return Arrays.stream(sms.split("")).map(Integer::parseInt).toArray(Integer[]::new);
    }
    public static List<Integer> generateShuffledListInteger() {
        List<Integer> numbers = new ArrayList<>();
        for (int i = 0; i <= 43; i++) {
            numbers.add(i);
        }
        Collections.shuffle(numbers);
        return numbers.subList(0,26);
    }

}
