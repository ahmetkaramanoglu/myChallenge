package com.bkm.bkm_server.util;

import com.bkm.bkm_server.exception.SoftOtpException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;


@Component
public class JsonUtil {
    private static ObjectMapper objectMapper = new ObjectMapper();

    public static String jsonToString(Object obj)  {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (Exception e) {
            throw new SoftOtpException(e.getMessage());
        }
    }

    //FARK NE?
    public static <T> T stringToJson(String json, Class<T> clazz) {
        try {
            return objectMapper.readValue(json, clazz);
        } catch (Exception e) {
            throw new SoftOtpException(e.getMessage());
        }
    }
}
