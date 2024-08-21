package com.bkm.bkm_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

@Component
public class SharedKey {
    private String sharedKey;

    @Bean
    public String getSharedKey() {
        return sharedKey;
    }

    public void setSharedKey(String sharedKey) {
        this.sharedKey = sharedKey;
    }
}
