package com.bkm.bkm_server.exception;

public enum Error {
    GENERAL_ERROR("-1", "Unexpected error"),
    USERDEVICE_NOT_FOUND("10404", "User not found"),
    CRYPTION_ERROR("10405", "Cryption error"),
    USERDEVICE_SAVE_ERROR("10406", "User device save error"),
    USERDEVICE_UPDATE_ERROR("10407", "User device update error"),
    TOTP_GENERATION_ERROR("10408", "TOTP error"),
    VERIFICATION_ERROR("10408", "Verification error"),
    INVALID_INPUT_ERROR("10409", "Invalid parameter error");

    Error(String errorCode, String errorDescription) {
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
    }

    private final String errorCode;
    private final String errorDescription;

    public String getErrorCode() {
        return errorCode;
    }

    public String getErrorDescription() {
        return errorDescription;
    }
}
