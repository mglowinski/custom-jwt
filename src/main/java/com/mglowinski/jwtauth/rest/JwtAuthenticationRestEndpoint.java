package com.mglowinski.jwtauth.rest;

import com.mglowinski.jwtauth.model.JwtRequest;
import com.mglowinski.jwtauth.model.JwtResponse;
import com.mglowinski.jwtauth.utils.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JwtAuthenticationRestEndpoint {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenUtil jwtTokenUtil;
    private final UserDetailsService userDetailsService;

    @PostMapping("/auth/token")
    public ResponseEntity<JwtResponse> authenticateUser(@RequestBody JwtRequest jwtRequest) {
        authenticate(jwtRequest);

        UserDetails userDetails = userDetailsService.loadUserByUsername(jwtRequest.getUsername());

        String token = jwtTokenUtil.generateToken(userDetails);

        return ResponseEntity.ok(new JwtResponse(token));
    }

    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello world");
    }

    private void authenticate(JwtRequest jwtRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        jwtRequest.getUsername(), jwtRequest.getPassword()));
    }

}
