package com.app.ecommerce.service;

import com.app.ecommerce.exchange.response.LoginResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;
    private final JwtService jwtService;

    public LoginResponse login(String userName, String password) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(userName, password)
        );

        String token = jwtService.generateToken(userName);
        return new LoginResponse(token, "Bearer",
                userDetailsService.loadUserByUsername(userName).getUsername(),
                "");
    }
}