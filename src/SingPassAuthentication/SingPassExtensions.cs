
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Net;

namespace SingPassAuthentication
{
    public static class SingPassExtensions
    {
        public static AuthenticationBuilder AddSingPass(this AuthenticationBuilder builder,
            string authenticationScheme, string displayName, Action<SingPassOptions> configurationOptions = null)
        {
            var singpassOptions = new SingPassOptions();
            if (configurationOptions != null) configurationOptions(singpassOptions);

            builder.AddOpenIdConnect(authenticationScheme, displayName, options =>
            {
                options.SaveTokens = true;
                options.SignInScheme = "idsrv.external";

                options.Authority = singpassOptions.Authority;
                options.ClientId = singpassOptions.ClientId;
                options.ResponseType = "code";
                options.CallbackPath = singpassOptions.CallbackPath;
                options.SignedOutRedirectUri = singpassOptions.SignedOutRedirectUri;

                options.Scope.Clear();
                options.Scope.Add("openid");

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    IssuerSigningKeyResolver = (token, securityToken, kid, tokenValidation) =>
                    {
                        if (string.IsNullOrEmpty(singpassOptions.ServerJwks))
                        {
                            using var webClient = new WebClient();
                            singpassOptions.ServerJwks = webClient.DownloadString(singpassOptions.ServerJwksUri);
                        }
                        return new JsonWebKeySet(singpassOptions.ServerJwks).GetSigningKeys();
                    },
                    ValidAudience = singpassOptions.ClientId,
                    ValidIssuer = singpassOptions.Authority,
                    ValidateIssuer = true,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true
                };

                options.EventsType = typeof(SingPassHandlers);
            });

            builder.Services.AddTransient<SingPassHandlers>();
            builder.Services.AddSingleton<SingpassService>();
            builder.Services.AddSingleton(singpassOptions);

            return builder;
        }
    }
}
