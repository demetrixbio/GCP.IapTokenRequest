using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Requests;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Google.Apis.Auth.OAuth2
{
    public static class ServiceAccountCredentialExtensions
    {
        static async Task<string> GetIapAccessTokenAsync(this ServiceAccountCredential @this, string oAuthClientId, DateTime? expires = null, CancellationToken? cancellationToken = null)
        {
            var now = DateTimeOffset.Now;

            var key = new RsaSecurityKey(@this.Key.ExportParameters(true));
            var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
            var token =
                new JwtSecurityToken(
                    issuer: @this.Id,
                    audience: GoogleAuthConsts.OidcTokenUrl,
                    signingCredentials: creds,
                    claims: new[] {
                        new Claim(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString()),
                        new Claim("target_audience", oAuthClientId)
                    },
                    expires: expires.GetValueOrDefault(now.AddMinutes(10).DateTime)
                );

            var jwtSigned = new JwtSecurityTokenHandler().WriteToken(token);
            var req = new GoogleAssertionTokenRequest { Assertion = jwtSigned };
            var response = await req.ExecuteAsync(
                    @this.HttpClient, 
                    @this.TokenServerUrl, 
                    cancellationToken.GetValueOrDefault(CancellationToken.None), 
                    @this.Clock
            );

            return response.IdToken;
        }
    }
}