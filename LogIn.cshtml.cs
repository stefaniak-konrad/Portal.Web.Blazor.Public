using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using EO.Serwis.Portal.ServiceLayer;
using EO.Serwis.Portal.ServiceLayer.DTO;
using EO.Serwis.Portal.Web.Blazor.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Serilog;

namespace EO.Serwis.Portal.Web.Blazor.Pages
{
    [AllowAnonymous]
    public class LogInModel : PageModel
    {
        public PortalServiceClient Client { get; }

        public LogInModel(PortalServiceClient clientFactory)
        {
            Client = clientFactory;
        }

        LoginModel model = new LoginModel();

        public string ReturnUrl { get; set; }

        public async Task<IActionResult> OnGetAsync(string paramUsername, string paramPassword)
        {
            if(paramUsername != null || paramUsername != "" && paramPassword != null || paramPassword != "")
            {
                string returnUrl = Url.Content("~/Zgloszenia");
                try
                {
                    // Clear the existing external cookie
                    await HttpContext
                        .SignOutAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme);
                }
                catch { }

                try
                {
                    Client.Client.Timeout = TimeSpan.FromMinutes(30);

                    UserDTO user;
                    user = Client.Login(paramUsername.ToLower(), paramPassword);

                    if (user == null)
                    {
                        model.Error = "Logowanie nie powiodło się!";
                    }

                    var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, string.Join(" ", user.Imie,user.Nazwisko)),
                    new Claim(ClaimTypes.Email, paramUsername.ToLower()),
                    new Claim(ClaimTypes.Sid, user.Id.ToString()),
                    new Claim(ClaimTypes.Role, "User")
                };

                    var claimsIdentity = new ClaimsIdentity(
                        claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var principal = new ClaimsPrincipal(claimsIdentity);

                    var authProperties = new AuthenticationProperties
                    {
                        ExpiresUtc = DateTime.UtcNow.AddMinutes(20),
                        IsPersistent = false,
                        AllowRefresh = false
                    };

                    await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                    return LocalRedirect(returnUrl);
                }
                catch (Exception ex)
                {
                    Log.Fatal(ex.ToString());
                }
                return LocalRedirect("~/");
            }
            return LocalRedirect("~/");
        }
    }
}
