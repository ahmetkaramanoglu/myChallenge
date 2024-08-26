package com.bkm.bkm_server.response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PayloadResponse {
    private String clientChallengeId;
    private String serverChallengeId;
    private int [] smsProtocol;
}
