package com.example;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * 
 * @author Yu-Hua Chang
 */
public class AzureAdJwtToken {

    protected final String token;

    // Header
    protected final String x5t;
    protected final String kid;

    // Payload
    protected final String issuer;
    protected final String ipAddr;
    protected final String name;
    protected final String uniqueName;
    
    public AzureAdJwtToken(String token) {
        this.token = token;

        String[] parts = token.split("\\.");
        
        // Header
        String headerStr = new String(Base64.getUrlDecoder().decode((parts[0])));
//        System.out.println(headerStr);
        JSONObject header = new JSONObject(headerStr);
//        System.out.println("typ = " + header.getString("typ"));
//        System.out.println("alg = " + header.getString("alg"));
//        System.out.println("x5t = " + header.getString("x5t"));
//        System.out.println("kid = " + header.getString("kid"));
//        System.out.println("---------------------------------");
        
        x5t = header.getString("x5t");
        kid = header.getString("kid");

        // Payload
        // reserved, public, and private claims.
        String payloadStr = new String(Base64.getUrlDecoder().decode((parts[1])));
//        System.out.println(payloadStr);
        JSONObject payload = new JSONObject(payloadStr);
//        System.out.println("aud = " + payload.getString("aud"));
//        System.out.println("iss = " + payload.getString("iss"));
//        System.out.println("ipaddr = " + payload.getString("ipaddr"));
//        System.out.println("name = " + payload.getString("name"));
//        System.out.println("unique_name = " + payload.getString("unique_name"));
//        System.out.println("upn = " + payload.getString("upn"));
//        System.out.println("---------------------------------");
        
        issuer = payload.getString("iss");
        ipAddr = payload.getString("ipaddr");
        name = payload.getString("name");
        uniqueName = payload.getString("unique_name");
    }
    
    /**
     *     1. go to here: https://login.microsoftonline.com/common/.well-known/openid-configuration
     *     2. check the value of "jwks_uri", which is "https://login.microsoftonline.com/common/discovery/keys"
     *     3. go to https://login.microsoftonline.com/common/discovery/keys
     *     4. get "kid" value from header, which is "Y4ueK2oaINQiQb5YEBSYVyDcpAU"
     *     5. search Y4ueK2oaINQiQb5YEBSYVyDcpAU in key file to get the key.
     *     
     *     (We can manually decode JWT token at https://jwt.io/ by copy'n'paste)
     *     to select the public key used to sign this token.
     *     (There are about three keys which are rotated about everyday.)
     *     
     * @throws IOException
     * @throws CertificateException 
     */
    protected PublicKey loadPublicKey() throws IOException, CertificateException {

        // Key Info (RSA PublicKey)
        String openidConfigStr = readUrl("https://login.microsoftonline.com/common/.well-known/openid-configuration");
//        System.out.println(openidConfigStr);
        JSONObject openidConfig = new JSONObject(openidConfigStr);
//        System.out.println("---------------------------------");

        String jwksUri = openidConfig.getString("jwks_uri");
//        System.out.println(jwksUri);
//        System.out.println("---------------------------------");
        
        String jwkConfigStr = readUrl(jwksUri);
//        System.out.println(jwkConfigStr);
        JSONObject jwkConfig = new JSONObject(jwkConfigStr);
//        System.out.println("---------------------------------");
        
        JSONArray keys = jwkConfig.getJSONArray("keys");
        for (int i = 0; i < keys.length(); i++) {
            JSONObject key = keys.getJSONObject(i);

            String kid = key.getString("kid");
            String x5t = key.getString("x5t");
            String n = key.getString("n");
            String e = key.getString("e");
            String x5c = key.getJSONArray("x5c").getString(0);

//            System.out.println("kid: " + kid);
//            System.out.println("x5t: " + x5t);
//            System.out.println("n: " + n);
//            System.out.println("e: " + e);
//            System.out.println("x5c: " + x5c);

            String keyStr = "-----BEGIN CERTIFICATE-----\r\n";
            String tmp = x5c;
            while (tmp.length() > 0) {
                if (tmp.length() > 64) {
                    String x = tmp.substring(0, 64);
                    keyStr += x + "\r\n";
                    tmp = tmp.substring(64);
                } else {
                    keyStr += tmp + "\r\n";
                    tmp = "";
                }
            }
            keyStr += "-----END CERTIFICATE-----\r\n";
//            System.out.println(keyStr);
            /*
             * go to https://jwt.io/ and copy'n'paste the thow jwt token to the left side, it will be decoded on the right side,
             * copy'n'past the public key (from ----BEGIN... to END CERT...) to the verify signature part, it will show signature verified.
             */
            
            //byte[] keyBytes = keyStr.getBytes();
            //byte[] keyBytes = x5c.getBytes();
            //byte[] keyBytes = Base64.getDecoder().decode(x5c);
            
//            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
//            KeyFactory kf = KeyFactory.getInstance("RSA");
//            PublicKey publicKey = kf.generatePublic(spec);
//            System.out.println(publicKey);
            
            // read certification
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            InputStream stream = new ByteArrayInputStream(keyStr.getBytes(StandardCharsets.US_ASCII));
            X509Certificate cer = (X509Certificate) fact.generateCertificate(stream);
//            System.out.println(cer);
            
            // get public key from certification
            PublicKey publicKey = cer.getPublicKey();
//            System.out.println(publicKey);
            
            if (this.kid.equals(kid)) {
                return publicKey;
            }
        }
        return null;
    }
    
    //TODO: cache content to file to prevent access internet everytime.
    protected String readUrl(String url) throws IOException {
        URL addr = new URL(url);
        StringBuilder sb = new StringBuilder();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(addr.openStream()))) {
            String inputLine = null;
            while ((inputLine = in.readLine()) != null) {
                sb.append(inputLine);
            }
        }
        return sb.toString();
    }
    
    public void verify() throws IOException, CertificateException {

        PublicKey publicKey = loadPublicKey();
        
//        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
//        cipher.init(Cipher.DECRYPT_MODE, publicKey);
//        byte[] encryptedbytes = cipher.doFinal(Base64.getUrlDecoder().decode(signatureStr.getBytes()));
//        String result = Base64.getUrlEncoder().encodeToString(encryptedbytes);
//        System.out.println("---------------------------------");
//        System.out.println(result);
//        System.out.println(parts[0] + parts[1]);
//        
//        System.out.println("---------------------------------");
        
        //TODO: possible decode without 3rd party library...
        JWTVerifier verifier = JWT.require(Algorithm.RSA256((RSAKey) publicKey)).withIssuer(issuer).build();
        DecodedJWT jwt = verifier.verify(token);
//        System.out.println("DecodedJWT");
//        System.out.println(jwt);
//        System.out.println("---------------------------------");
    }

    public String getIpAddr() {
        return ipAddr;
    }

    public String getName() {
        return name;
    }

    public String getUniqueName() {
        return uniqueName;
    }

    @Override
    public String toString() {
        return "AzureAdJwtToken [issuer=" + issuer + ", ipAddr=" + ipAddr + ", name=" + name + ", uniqueName="
                + uniqueName + "]";
    }
}
