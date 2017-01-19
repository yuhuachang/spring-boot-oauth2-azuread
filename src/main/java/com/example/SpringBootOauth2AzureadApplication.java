package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultRequestEnhancer;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.util.MultiValueMap;

@SpringBootApplication
@EnableOAuth2Sso
public class SpringBootOauth2AzureadApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootOauth2AzureadApplication.class, args);
    }

    @Bean
    public UserInfoRestTemplateCustomizer getUserInfoRestTemplateCustomizer() {
        return new UserInfoRestTemplateCustomizer() {
            @Override
            public void customize(OAuth2RestTemplate template) {
                template.setAccessTokenProvider(new MyAuthorizationCodeAccessTokenProvider());
            }
        };
    }
    
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


}
