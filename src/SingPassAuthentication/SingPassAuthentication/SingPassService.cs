using IdentityModel;
using Jering.Javascript.NodeJS;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SingPassAuthentication
{
    public class SingpassService
    {
        private readonly SingPassOptions _configuration;

        public SingpassService(SingPassOptions configuration)
        {
            _configuration = configuration;
        }

        public string CreateClientToken()
        {
            var now = DateTime.UtcNow;
            var signingKey = new JsonWebKeySet(_configuration.ClientJwks).GetSigningKeys().First();

            var clientAssertionToken = new JwtSecurityToken(
                _configuration.ClientId,
                _configuration.TokenEndpoint,
                new List<Claim>()
                {
                    new Claim(JwtClaimTypes.Subject, _configuration.ClientId),
                    new Claim(JwtClaimTypes.Issuer, _configuration.ClientId),
                    new Claim(JwtClaimTypes.Audience, _configuration.Authority),
                    new Claim(JwtClaimTypes.IssuedAt, now.ToEpochTime().ToString(), ClaimValueTypes.Integer64),
                    new Claim(JwtClaimTypes.Expiration, now.AddMinutes(_configuration.SkewInMinutes).ToEpochTime().ToString(), ClaimValueTypes.Integer64 )
                },
                now,
                now.AddMinutes(_configuration.SkewInMinutes),
                new SigningCredentials(signingKey, _configuration.SigningAlgorithm.ToString())
            );

            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.OutboundClaimTypeMap.Clear();

            return tokenHandler.WriteToken(clientAssertionToken);
        }

        public async Task<string> DecryptToken(string jwks, string jwt)
        {
            var decryptTokenJS = @"
const jose = require('node-jose');
module.exports = async (jwkset, token) => {
      const handlers = {};
      const opts = {
          handlers
      };

      var keystore = jose.JWK.createKeyStore();
      var keystore = await jose.JWK.asKeyStore(jwkset);

      const result = await jose.JWE.createDecrypt(keystore).decrypt(token);

      return result.payload.toString();
      return token;
};
";
            return await StaticNodeJSService.InvokeFromStringAsync<string>(
                    decryptTokenJS,
                    args: new[] { jwks, jwt });
        }

    }
}
