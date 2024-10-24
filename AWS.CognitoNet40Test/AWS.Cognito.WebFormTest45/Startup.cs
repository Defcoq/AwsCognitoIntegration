using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(AWS.Cognito.WebFormTest45.Startup))]

namespace AWS.Cognito.WebFormTest45
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // Configure cookie authentication
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "ApplicationCookie",
                LoginPath = new PathString("/Account/Login")
            });

            // Configure OpenID Connect (e.g., Amazon Cognito)
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = "your-cognito-client-id",
                Authority = "https://cognito-idp.{region}.amazonaws.com/{user-pool-id}",
                RedirectUri = "https://your-app-url/signin-oidc",
                ResponseType = "code",
                Scope = "openid profile",
                SignInAsAuthenticationType = "ApplicationCookie"
            });
        }
    }
}
