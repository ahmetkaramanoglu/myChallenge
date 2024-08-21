package com.bkm.bkm_server.service;


import com.bkm.bkm_server.dto.UserDto;
import com.bkm.bkm_server.dto.converter.UserDtoConverter;
import com.bkm.bkm_server.model.User;
import com.bkm.bkm_server.repository.UserRepository;
import com.bkm.bkm_server.request.CreateUserRequest;
import com.bkm.bkm_server.request.UserLoginRequest;
import com.bkm.bkm_server.util.JwtUtil;
import jakarta.persistence.EntityNotFoundException;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@AllArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final UserDtoConverter userDtoConverter;
    private final PasswordEncoder passwordEncoder;
    //Username'e gore bulacak protected
    //register islemleri yapabilirsin ama simdilik mock bir kullanici olusturup onu login edip ona jwt don.

    protected Optional<User> getUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = getUserByUsername(username);
        return user.orElseThrow(EntityNotFoundException::new);
    }

    public String login(UserLoginRequest userLoginRequest) {
        User user = userRepository.findByUsername(userLoginRequest.getUsername()).orElseThrow(EntityNotFoundException::new);
        if(passwordEncoder.matches(userLoginRequest.getPassword(), user.getPassword())) {
            System.out.println("username ve password matched");
            System.out.println("jwt token " + JwtUtil.generateToken(userLoginRequest.getUsername()));
            return JwtUtil.generateToken(userLoginRequest.getUsername());
        }
        else{
            throw new EntityNotFoundException();
        }
    }

    public UserDto register(CreateUserRequest createUserRequest) {
        User user = new User(createUserRequest.getUsername(), passwordEncoder.encode(createUserRequest.getPassword()), createUserRequest.getAuthorities());
        return userDtoConverter.convertToUserDto(userRepository.save(user));
    }


}
