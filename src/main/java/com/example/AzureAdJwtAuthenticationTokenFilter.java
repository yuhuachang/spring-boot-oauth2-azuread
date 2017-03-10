package com.example;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

@Service
public class AzureAdJwtAuthenticationTokenFilter extends OncePerRequestFilter {
    
    private static final Logger log = LoggerFactory.getLogger(AzureAdJwtAuthenticationTokenFilter.class);

    private static final String TOKEN_HEADER = "Authorization";
    private static final String TOKEN_TYPE = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // Retrieve authorization token from header.
        String tmp = request.getHeader(TOKEN_HEADER);

        if (tmp != null) {
            if (tmp.startsWith(TOKEN_TYPE)) {
                String jwtText = tmp.substring(TOKEN_TYPE.length());

                if (log.isDebugEnabled()) {
                    log.debug("Raw JWT token: >>{}<<", jwtText);
                }

                // Create Azure jwt token.
                AzureAdJwtToken jwt = new AzureAdJwtToken(jwtText);

                if (log.isDebugEnabled()) {
                    log.debug("JWT: {}", jwt);
                }

                try {
                    // Verify Azure jwt token.
                    jwt.verify();
                    if (log.isDebugEnabled()) {
                        log.debug("Token verification success!");
                    }

                    // If token verification success, create Spring authentication object and grant authorities.
                    List<GrantedAuthority> authorities = new ArrayList<>();

                    // set roles
                    if ("john@example.com".equals(jwt.getUniqueName())) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                    } else if ("marry@example.com".equals(jwt.getUniqueName())) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                    }

                    Authentication authentication = new PreAuthenticatedAuthenticationToken(jwt, null, authorities);
                    authentication.setAuthenticated(true);
                    log.info("Request token verification success. {}", authentication);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    
                } catch (CertificateException e) {
                    throw new RuntimeException(e);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("This request does not contain any authorization token.");
            }
        }

        filterChain.doFilter(request, response);
    }
}