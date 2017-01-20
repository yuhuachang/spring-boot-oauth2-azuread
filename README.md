# spring-boot-oauth2-azuread
SpringBoot OAuth2 Authentication with Microsoft AzureAD

Here follows the tutorial from https://spring.io/guides/tutorials/spring-boot-oauth2/ but change from Facebook to AzureAD.

# Todos
There seems to be a minor bug that this app will attempt to use unauthorized resource /user before login and will be stopped from redirecting.  We see an error in JavaScript console.

The logout function only logout from Spring App, not logout from AzureAD. 

# References
Spring OAuth2:
   https://spring.io/guides/tutorials/spring-boot-oauth2/
   https://spring.io/guides/tutorials/spring-security-and-angular-js/

MS AAD doc:
   https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols-oauth-code
   https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-scopes

AAD auth process:
   http://simonjaeger.com/microsoft-graph-authentication-with-azure-ad/

MS JWT token doc:
   https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-tokens
   http://calebb.net/

Enhancer:
   http://statemachine.hatenablog.com/entry/2016/04/19/155920
   http://stackoverflow.com/questions/36158849/how-do-i-customize-the-spring-boot-accesstokenprovider
   https://github.com/bmillerbma/tut-spring-boot-oauth2/tree/aad/simple

MS Graph API
   https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-graph-api-quickstart
   https://msdn.microsoft.com/en-us/library/azure/ad/graph/api/signed-in-user-operations
