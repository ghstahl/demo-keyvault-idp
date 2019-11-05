# demo-keyvault-idp
IdentityServer4 Demo IDP

## Build (Powershell)
{ROOT}/src/build.ps1

## Configuration 
I followed these directions when building the demo.
[identityserver4-azure-keyvault](http://www.rosengren.me/blog/identityserver4-azure-keyvault)  



copy [.env.example](src/.env.example) to {ROOT}/src/.env

```
.env

Identity_AzureAd_ClientId=<secret>
Identity_AzureAd_ClientSecret=<secret>
Identity_KeyVault=P7KeyValut
Identity_KeyIdentifier=P7IdentityServer4SelfSigned
```



## Finally
Connect to [http://localhost:4700/](http://localhost:4700/)