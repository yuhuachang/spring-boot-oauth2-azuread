package com.example;

import java.security.Principal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// our services are stateless and can be called from anywhere.
@CrossOrigin
@RestController
public class MyController {

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @RequestMapping("/principal")
    public Principal principal(Principal principal) {
        return principal;
    }
    
    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/users")
    public String users() {
        return "I have users permission";
    }
    
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public String admin() {
        return "I have admin permission";
    }
}
