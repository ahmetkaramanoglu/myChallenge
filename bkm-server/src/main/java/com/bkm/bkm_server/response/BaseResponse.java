package com.bkm.bkm_server.response;

import lombok.Data;

@Data
public class BaseResponse<T> {
    private Status status;
    private T data;
    public BaseResponse(T data) {
        this.status = new Status(true,null,null);
        this.data = data;
    }
}
