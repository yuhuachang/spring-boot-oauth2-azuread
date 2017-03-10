package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultRequestEnhancer;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.MultiValueMap;

@EnableOAuth2Sso // enabling login from OAuth (AzureAD)
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // enabling the authorization check before each service call.
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AzureAdJwtAuthenticationTokenFilter azureAdJwtAuthenticationTokenFilter;
    
    // Required by AzureAD only
    @Bean
    public UserInfoRestTemplateCustomizer getUserInfoRestTemplateCustomizer() {
        return new UserInfoRestTemplateCustomizer() {
            @Override
            public void customize(OAuth2RestTemplate template) {
                template.setAccessTokenProvider(new MyAuthorizationCodeAccessTokenProvider());
            }
        };
    }

    // Required by AzureAD only
    protected class MyAuthorizationCodeAccessTokenProvider extends AuthorizationCodeAccessTokenProvider {
        public MyAuthorizationCodeAccessTokenProvider() {
            setTokenRequestEnhancer(new DefaultRequestEnhancer() {
                @Override
                public void enhance(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form, HttpHeaders headers) {
                    super.enhance(request, resource, form, headers);
                    form.set("resource", "https://graph.windows.net/");
                }
            });
        }
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        
        // allow loading our single page application by everyone. not required if the page is hosted somewhere else.
        http.authorizeRequests().antMatchers("/").permitAll();
        
        // allow logout
        http.logout().logoutSuccessUrl("/").permitAll();

        // all  other services are protected.
        http.authorizeRequests().anyRequest().authenticated();

        // we are using token based authentication. csrf is not required.
        http.csrf().disable();
        
        // need a filter to validate the Jwt token from AzureAD and assign roles.
        // without this, the token will not be validated and the role is always ROLE_USER.
        http.addFilterBefore(azureAdJwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
