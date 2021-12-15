using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SingPassAuthentication
{
    public class SingPassHandlers : OpenIdConnectEvents
    {
        private readonly SingpassService _assertionService;
        private readonly SingPassOptions _configuration;
        private readonly IMemoryCache _memoryCache;
        private IDistributedCache _distributedCache;

        public SingPassHandlers(SingpassService assertionService, SingPassOptions configuration, IMemoryCache memoryCache = null, IDistributedCache distributdCache = null)
        {
            _assertionService = assertionService;
            _configuration = configuration;
            if (memoryCache != null)
            {
                _memoryCache = memoryCache;
            }
            if (distributdCache != null)
            {
                _distributedCache = distributdCache;
            }
        }

        public override Task RedirectToIdentityProvider(RedirectContext context)
        {
            var cacheKey = $"{Guid.NewGuid().ToString("N")}-{DateTime.UtcNow:ddMMyyyhhmmss}";
            context.ProtocolMessage.State = cacheKey;

            context.Properties.Items.Add(OpenIdConnectDefaults.RedirectUriForCodePropertiesKey, context.ProtocolMessage.RedirectUri);
            context.Response.Redirect(context.ProtocolMessage.CreateAuthenticationRequestUrl());
            if (CacheExists)
            {
                var value = context.Options.StateDataFormat.Protect(context.Properties);
                SetCache(cacheKey, value);
            }
            context.HandleResponse();
            return Task.CompletedTask;
        }

        public override Task MessageReceived(MessageReceivedContext context)
        {
            if (TryGetCache(context.ProtocolMessage.State, out var cacheValue))
            {
                context.ProtocolMessage.State = cacheValue;
                context.Properties = context.Options.StateDataFormat.Unprotect(context.ProtocolMessage.State);
            }
            return Task.CompletedTask;
        }

        public override Task AuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
        {
            context.TokenEndpointRequest.ClientAssertionType = OidcConstants.ClientAssertionTypes.JwtBearer;
            context.TokenEndpointRequest.ClientAssertion = _assertionService.CreateClientToken();
            return Task.CompletedTask;
        }

        public override async Task TokenResponseReceived(TokenResponseReceivedContext context)
        {
            // Decrypt here
            var decryptedIdToken = await _assertionService.DecryptToken(_configuration.ClientJwks, context.TokenEndpointResponse.IdToken);

            // Need to manually validate decrypted token
            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.ValidateToken(decryptedIdToken, context.Options.TokenValidationParameters, out var securityToken);

            context.TokenEndpointResponse.IdToken = decryptedIdToken;
            await base.TokenResponseReceived(context);
        }


        public override Task TicketReceived(TicketReceivedContext context)
        {
            var identity = context.Principal.Identity as ClaimsIdentity;
            identity.Label = "SingPass";

            if (_configuration.SingpassClaimHandler != null)
            {
                _configuration.SingpassClaimHandler(identity);
            }

            return base.TicketReceived(context);
        }


        public override Task RedirectToIdentityProviderForSignOut(RedirectContext context)
        {
            context.Response.Redirect(context.Options.SignedOutRedirectUri);
            context.HandleResponse();

            return Task.CompletedTask;
        }

        private bool CacheExists
        {
            get
            {
                return (_memoryCache != null || _distributedCache != null);
            }
        }

        private void SetCache(string cacheKey, string value)
        {
            if (_memoryCache != null)
            {
                _memoryCache.Set(cacheKey, value, new MemoryCacheEntryOptions { AbsoluteExpiration = DateTime.Now.AddMinutes(2) });
            }

            if (_distributedCache != null)
            {
                _distributedCache.SetString(cacheKey, value, new DistributedCacheEntryOptions { AbsoluteExpiration = DateTime.Now.AddMinutes(2) });
            }
        }

        private bool TryGetCache(string cacheKey, out string result)
        {
            result = String.Empty;
            if (string.IsNullOrEmpty(cacheKey)) return false;

            if (_distributedCache != null) // preference
            {
                result = _distributedCache.GetString(cacheKey);
            }

            if (string.IsNullOrEmpty(result) && _memoryCache != null)
            {
                result = _memoryCache.Get<string>(cacheKey);
            }

            return !string.IsNullOrEmpty(result);
        }
    }
}
