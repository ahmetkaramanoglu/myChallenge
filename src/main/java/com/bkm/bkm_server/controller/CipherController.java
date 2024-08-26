package com.bkm.bkm_server.controller;

import com.bkm.bkm_server.request.EncryptRequest;
import com.bkm.bkm_server.request.PublicKeyRequest;
import com.bkm.bkm_server.request.UserLoginRequest;
import com.bkm.bkm_server.response.CipherResponse;
import com.bkm.bkm_server.response.EncryptResponse;
import com.bkm.bkm_server.response.LoginResponse;
import com.bkm.bkm_server.service.CipherService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@AllArgsConstructor
@RestController
@RequestMapping("/bkm/cipher/v1")
public class CipherController {
    private final CipherService cipherService;

    @PostMapping("/receive-public-key")
    public CipherResponse keyExchange(@RequestBody PublicKeyRequest request) throws Exception {
        return new CipherResponse(cipherService.sendToPublicKeyWithJWE(request.getEncryptedJWE()),"version");
    }

    @PostMapping("encrypt-test")
    public EncryptResponse encryptTest(@RequestBody EncryptRequest request) throws Exception {
        System.out.println("Sifreli veri: " + request.getEncryptData());
        return new EncryptResponse(cipherService.decrypt(request.getEncryptData()));
    }
    @PostMapping("login-request")
    public LoginResponse loginRequestTest(@RequestBody UserLoginRequest request) throws Exception {
        return new LoginResponse(cipherService.decryptLoginRequest(request));
    }

}
