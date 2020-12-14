using Basics.CustomPolicyProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Basics.Controllers
{
    public class HomeController : Controller
    {
        private readonly IAuthorizationService _authorizationService;
        public HomeController(IAuthorizationService authorizationService)
        {
            _authorizationService = authorizationService;
        }


        private object grandmaIdentity;
        private object builder;

        public IActionResult Index()
        {
            //home page
            return View();
        }

        [Authorize]
        public IActionResult Secret()
        {
            return View();
        }
        
        [Authorize(Policy = "Claim.DoB")]
        public IActionResult SecretPolicy()
        {
            return View("Secret");
        }

        [Authorize(Roles = "Admin")]
        public IActionResult SecretRole()
        {
            return View("Secret");
        }
        
        [SecurityLevel(5)]
        public IActionResult SecretLevel()
        {
            return View("Secret");
        }

        [SecurityLevel(10)]
        public IActionResult SecretHigherLevel()
        {
            return View("Secret");
        }


        [AllowAnonymous]
        public IActionResult Authenticate()
        {
            var grandmaClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "Lin"),
                new Claim(ClaimTypes.Email, "Lin@gmail.com"),
                new Claim(ClaimTypes.DateOfBirth, "05/03/1996"),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim(ClaimTypes.Role, "AdminTwo"),
                new Claim(DynamicPilicies.SecurityLevel, "7"),
                new Claim("Grandma.Says", "very nice"),
            };

            var licenseClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "Xinglin Peng"),
                new Claim("DrivingLicense", "A"),
            };
                
            var grandmaIdentity = new ClaimsIdentity(grandmaClaims, "Grandma Identity");
            var licenseIdentity = new ClaimsIdentity(licenseClaims, "Government");

            var userPrincipal = new ClaimsPrincipal(new[] { grandmaIdentity, licenseIdentity });
            //-----------------------------------------------------
            HttpContext.SignInAsync(userPrincipal);
            //where actually going to be creating the user
            return RedirectToAction("Index");
            
        }

        //video 4 18mins
        public async Task<IActionResult> DoStuff(
            [FromServices] IAuthorizationService authorizationService)
        {
            // we are doing stuff here

            var builder = new AuthorizationPolicyBuilder("Schema");
            var customPolicy = builder.RequireClaim("Hello").Build();

            var authResult = await _authorizationService.AuthorizeAsync(User, customPolicy);
            
            if(authResult.Succeeded)
            {
                return View("Index");
            }
            return View("Index");
        }
    }
}
