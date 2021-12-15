using System;
using System.Security.Claims;

namespace SingPassAuthentication
{
    public class SingPassOptions
    {
        public string Authority { get; set; }
        public string ClientId { get; set; }
        public string ClientJwks { get; set; }
        public string CallbackPath { get; set; }
        public string SignedOutRedirectUri { get; set; }
        public string TokenEndpoint
        {
            get
            {
                return _tokenEndpoint ?? $"{Authority}/token";
            }
            set
            {
                _tokenEndpoint = value;
            }

        }

        public string ServerJwksUri
        {
            get
            {
                return _serverJwksUri ?? $"{Authority}/.well-known/keys";
            }
            set
            {
                _serverJwksUri = value;
            }
        }
        public int SkewInMinutes { get; set; }
        public string ServerJwks { get; set; }

        public SigningAlgorithm SigningAlgorithm { get; set; }
        public Action<ClaimsIdentity> SingpassClaimHandler { get; set; }

        // Backing field
        private string _tokenEndpoint;
        private string _serverJwksUri;

        public SingPassOptions()
        {
            CallbackPath = "/signin-singpass";
            SignedOutRedirectUri = "/";
            SkewInMinutes = 2;
            SigningAlgorithm = SigningAlgorithm.ES256;

            SingpassClaimHandler = identity =>
            {
                var singpassIdentifier = identity.FindFirst(ClaimTypes.NameIdentifier);

                var singpass = singpassIdentifier.Value.Split(",");
                var nric = singpass[0].Split("=")[1];
                var uid = singpass[1].Split("=")[1];
                identity.RemoveClaim(singpassIdentifier);

                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, uid, ClaimValueTypes.String, "SingPass"));
                identity.AddClaim(new Claim(ClaimTypes.Name, $"{nric.Substring(0, 1)}XXX{nric.Substring(nric.Length - 5)}", ClaimValueTypes.String, "SingPass"));
            };
        }
    }
}
