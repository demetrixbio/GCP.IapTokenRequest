[<AutoOpen>] 
module Google.Apis.Auth.OAuth2.ServiceAccountCredentialExtensions 

open System
open System.Security.Claims
open System.IdentityModel.Tokens.Jwt
open Microsoft.IdentityModel.Tokens
open Google.Apis.Auth.OAuth2.Requests

type ServiceAccountCredential with
    member this.GetIapAccessTokenAsync(oAuthClientId: string, ?expires: DateTime) =
        async {
            let now = DateTimeOffset.Now

            let key = RsaSecurityKey(this.Key.ExportParameters(true))
            let creds = SigningCredentials(key, SecurityAlgorithms.RsaSha256)
            let token = 
                JwtSecurityToken(
                    issuer = this.Id, 
                    audience = GoogleAuthConsts.OidcTokenUrl, 
                    signingCredentials = creds,
                    claims = [ 
                        Claim( JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString())
                        Claim("target_audience", oAuthClientId) 
                    ],
                    expires = Nullable( defaultArg expires (now.AddMinutes(10.).DateTime))
                )

            let jwtSigned = JwtSecurityTokenHandler().WriteToken(token)
            let req = GoogleAssertionTokenRequest(Assertion = jwtSigned)
            let! response = 
                req.ExecuteAsync( this.HttpClient, this.TokenServerUrl, Async.DefaultCancellationToken, this.Clock)
                |> Async.AwaitTask

            return response.IdToken
        }