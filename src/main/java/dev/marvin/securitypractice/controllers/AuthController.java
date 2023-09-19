package dev.marvin.securitypractice.controllers;

import dev.marvin.securitypractice.config.JWTUtils;
import dev.marvin.securitypractice.dao.UserDAO;
import dev.marvin.securitypractice.dto.AuthenticationRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserDAO userDAO;
    private final JWTUtils jwtUtils;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody AuthenticationRequest request) {
       authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

       final UserDetails userDetails = userDAO.findUserByEmail(request.getEmail());
       if(userDetails != null) {
           return ResponseEntity.ok(jwtUtils.generateToken(userDetails));
       }

       return ResponseEntity.status(400).body("Something went wrong");
    }
}
