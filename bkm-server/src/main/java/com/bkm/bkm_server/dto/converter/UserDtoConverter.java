package com.bkm.bkm_server.dto.converter;


import com.bkm.bkm_server.dto.UserDto;
import com.bkm.bkm_server.model.User;
import org.springframework.stereotype.Component;

@Component
public class UserDtoConverter {
    public UserDto convertToUserDto(User from) {
        return new UserDto(from.getUsername(), from.getPassword());
    }
}
