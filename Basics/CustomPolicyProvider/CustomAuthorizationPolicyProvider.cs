using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Basics.CustomPolicyProvider
{
    public class SecurityLevelAttribute : AuthorizeAttribute
    {
        public SecurityLevelAttribute(int level)
        {
            Policy = $"{DynamicPilicies.SecurityLevel}.{level}";
        }
    }
   
    // {type}
    public static class DynamicPilicies
    {
        public static IEnumerable<string> Get()
        {
            yield return SecurityLevel;
            yield return Rank;

        }

        public const string SecurityLevel = "SecurityLeve";
        public const string Rank = "Rank";
    }

    public static class DynamicAuthorizationPilicyFactory
    {
        public static AuthorizationPolicy Create(string policyName)
        {
            var parts = policyName.Split('.');
            var type = parts.First();
            var value = parts.Last();

            switch(type)
            {
                case DynamicPilicies.Rank:
                    return new AuthorizationPolicyBuilder()
                        .RequireClaim("Rank", value)
                        .Build();
                case DynamicPilicies.SecurityLevel:
                    return new AuthorizationPolicyBuilder()
                        .AddRequirements(new SecurityLevelRequirenment(Convert.ToInt32(value)))
                        .Build();
                default:
                    return null;
            }
        }
    }

    public class SecurityLevelRequirenment : IAuthorizationRequirement
    {
        public int Level { get; }
        public SecurityLevelRequirenment(int level)
        {
            Level = level;
        }
    }

    public class SecurityLevelHandler : AuthorizationHandler<SecurityLevelRequirenment>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context, 
            SecurityLevelRequirenment requirement)
        {
            var claimValue = Convert.ToInt32(context.User.Claims
                .FirstOrDefault(x => x.Type == DynamicPilicies.SecurityLevel)
                ?.Value ?? "0");

            if(requirement.Level <= claimValue)
            {
                context.Succeed(requirement);
            }
            return Task.CompletedTask;
        }
    }

    public class CustomAuthorizationPolicyProvider
        : DefaultAuthorizationPolicyProvider
    {
        public CustomAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options) : base (options)
        {

        }


        // {type}.{value}
        public override Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            foreach(var customPolicy in DynamicPilicies.Get())
            {
                if (policyName.StartsWith(customPolicy))
                {
                    var policy = DynamicAuthorizationPilicyFactory.Create(policyName);

                    return Task.FromResult(policy);
                }
            }

            return base.GetPolicyAsync(policyName);
        }
    }
}
