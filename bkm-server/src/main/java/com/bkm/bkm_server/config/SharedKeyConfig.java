package com.bkm.bkm_server.config;

import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@Configuration
public class SharedKeyConfig {
    private SecretKey sharedKey;

    public void setSharedKey(SecretKey sharedKey) {
        System.out.println("SharedKeyConfig set shared key " + sharedKey);
        this.sharedKey = sharedKey;
    }

}
