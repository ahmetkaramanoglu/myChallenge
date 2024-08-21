package com.bkm.bkm_server.annotation.encryption;


import com.bkm.bkm_server.response.BaseResponse;
import com.bkm.bkm_server.service.EncryptionUtilService;
import lombok.AllArgsConstructor;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

@ControllerAdvice
@Component
@AllArgsConstructor
public class EncryptionControllerAdvice implements ResponseBodyAdvice<BaseResponse<?>> {

    private final EncryptionUtilService encryptionService;
    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return returnType.hasMethodAnnotation(Encrypted.class);
    }
    @Override
    public BaseResponse<?>  beforeBodyWrite(BaseResponse<?> body, MethodParameter returnType, MediaType mediaType,
                                  Class<? extends HttpMessageConverter<?>> converterType,
                                  ServerHttpRequest request, ServerHttpResponse response) {
        try {
            Object data = body.getData();
            if (data != null) {
                String encryptedData = encryptionService.encryptData(data);
                BaseResponse<Object> encryptedResponse = new BaseResponse<>(encryptedData);
                return encryptedResponse;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return body;
    }
}