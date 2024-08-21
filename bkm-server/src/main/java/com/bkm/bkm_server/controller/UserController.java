package com.bkm.bkm_server.controller;

import com.bkm.bkm_server.annotation.decryption.Decrypted;
import com.bkm.bkm_server.annotation.encryption.Encrypted;
import com.bkm.bkm_server.dto.UserDto;
import com.bkm.bkm_server.request.CreateUserRequest;
import com.bkm.bkm_server.request.UserLoginRequest;
import com.bkm.bkm_server.response.BaseResponse;
import com.bkm.bkm_server.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/bkm/user")
@AllArgsConstructor
public class UserController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    @PostMapping("/register")
    public BaseResponse<UserDto> register(@RequestBody CreateUserRequest createUserRequest) {
        System.out.println("user: " + createUserRequest);
        return new BaseResponse<>(userService.register(createUserRequest));
    }
    @PostMapping("/getAccessToken")
    public BaseResponse<String> getAccessToken(@RequestBody UserLoginRequest userLoginRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                userLoginRequest.getUsername(),
                userLoginRequest.getPassword()));
        if (authentication.isAuthenticated()) {
            System.out.println("user authenticated");
            return new BaseResponse<>(userService.login(userLoginRequest));
        }
        throw new UsernameNotFoundException("invalid username: " + userLoginRequest.getUsername());
    }

//    @PostMapping("/login")
//    public String login(@RequestBody UserLoginRequest userLoginRequest) {
//        return userService.login(userLoginRequest);
//    }

    @Encrypted
    @PostMapping("/test")
    public BaseResponse<UserDto> encrypTest(@RequestBody UserDto userDto) throws Exception {
        return new BaseResponse<>(userDto);
    }

    @PostMapping("/test-decrypt")
    public BaseResponse<UserDto> decryptTest(@Decrypted UserDto userDto){
        System.out.println("user: " + userDto);
        return new BaseResponse<>(userDto);
    }

}
