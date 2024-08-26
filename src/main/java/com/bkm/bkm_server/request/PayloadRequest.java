package com.bkm.bkm_server.request;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PayloadRequest {
    private String clientChallengeId;
    private int [] secretProtocol;
    @JsonProperty("ESDKPUB")
    private String ESDKPUB;
}
