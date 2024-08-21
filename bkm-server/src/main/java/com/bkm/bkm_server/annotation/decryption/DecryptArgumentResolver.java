package com.bkm.bkm_server.annotation.decryption;

import com.bkm.bkm_server.service.EncryptionUtilService;
import com.bkm.bkm_server.util.JsonUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.util.stream.Collectors;

@ControllerAdvice
@Component
@AllArgsConstructor
public class DecryptArgumentResolver implements HandlerMethodArgumentResolver {

    private final EncryptionUtilService encryptionService;
    private final ObjectMapper objectMapper;
    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(Decrypted.class);
    }
    @Override
    public Object resolveArgument(MethodParameter parameter,
                                  ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest,
                                  WebDataBinderFactory binderFactory) throws Exception {

        HttpServletRequest request = webRequest.getNativeRequest(HttpServletRequest.class);
        String body = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));
        JsonNode rootNode = objectMapper.readTree(body);
        JsonNode dataNode = rootNode.path("data");
        if (dataNode.isMissingNode()) {
            throw new IllegalArgumentException("Missing 'data' field in the request body");
        }
        String encryptedData = dataNode.asText();
        String decryptedData = encryptionService.decryptData(encryptedData);
        Object data = JsonUtil.stringToJson(decryptedData, parameter.getParameterType());
        return data;
    }
}
