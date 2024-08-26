package com.bkm.bkm_server.service;


import com.bkm.bkm_server.config.SharedKey;
import com.bkm.bkm_server.util.CipherUtilECDH;
import com.bkm.bkm_server.util.JsonUtil;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;


@Component
@AllArgsConstructor
public class EncryptionUtilService<T> {

    private final SharedKey sharedKey;
    public String encryptData(T t)  {
        String secretKey = sharedKey.getSharedKey();
        String jsonString = JsonUtil.jsonToString(t);
        return CipherUtilECDH.encryptSymmetric(jsonString, CipherUtilECDH.decodeSecretKey(secretKey));
    }
    public String decryptData(String encryptedData)  {
        String secretKey = sharedKey.getSharedKey();
        String decryptedString = CipherUtilECDH.decryptSymmetric(encryptedData, CipherUtilECDH.decodeSecretKey(secretKey));
        return decryptedString;
    }
}
