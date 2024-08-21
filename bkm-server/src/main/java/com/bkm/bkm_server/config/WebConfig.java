package com.bkm.bkm_server.config;

import com.bkm.bkm_server.annotation.decryption.DecryptArgumentResolver;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
@AllArgsConstructor
public class WebConfig implements WebMvcConfigurer {

    private final DecryptArgumentResolver decryptArgumentResolver;
    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(decryptArgumentResolver);
    }
}
