package com.keyup.auth.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyup.auth.service.JWTService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private JWTService jwtService;
    private String secretKey;


    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService, String secretKey) {
        super(authenticationManager);
        this.jwtService = jwtService;
        this.secretKey = secretKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        String token = request.getHeader("Authorization");

        if (requiresAuthentication(token)) {
            UsernamePasswordAuthenticationToken authentication = null;
            if (jwtService.validate(token)) {
                authentication = new UsernamePasswordAuthenticationToken(jwtService.getUsername(token), null, jwtService.getRoles(token));
            }

            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        } else {
            Map<String, Object> body = new HashMap<>();
            body.put("message", "Login error: username not authenticated");

            response.getWriter().write(new ObjectMapper().writeValueAsString(body));
            response.setStatus(404);
            response.setContentType("application/json");
        }

    }

    private boolean requiresAuthentication(String header) {
        if (header == null || !header.startsWith("Bearer ")) {
            return false;
        }
        return true;
    }
}
