using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace AWS.Cognito.WebFormTest45
{
    public partial class _Default : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (HttpContext.Current.User.Identity.IsAuthenticated)
            {
                // The logged-in user's claims principal
                ClaimsPrincipal principal = HttpContext.Current.User as ClaimsPrincipal;

                // Retrieve the user's username (usually stored in the "sub" claim in Cognito)
                var username = principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                // Example of retrieving other claim information like email
                var email = principal?.FindFirst(ClaimTypes.Email)?.Value;

                // Display the user's username and email on the page (or use it in your logic)
                Response.Write($"Username: {username} <br />");
                Response.Write($"Email: {email}");
            }
            else
            {
                // If the user is not authenticated, redirect to the login page
                Response.Redirect("/Account/Login");
            }

            #region   scenario chiamato interfaccia di login ospitata (Hosted UI) COGNITO 
            string clientId = "tuo-client-id";  // Inserisci il tuo client ID di Cognito
            string domain = "tuo-dominio-cognito";  // Il dominio di Cognito (es: "yourdomain.auth")
            string region = "your-region";  // La tua regione AWS (es: "us-east-1")
            string redirectUri = "https://tuo-dominio/CognitoCallback.aspx";  // La tua URL di callback

            // Costruisci l'URL di login di Cognito con i parametri appropriati
            string loginUrl = string.Format("https://{0}.auth.{1}.amazoncognito.com/login?response_type=code&client_id={2}&redirect_uri={3}",
                                             domain, region, clientId, redirectUri);

            // Reindirizza l'utente alla pagina di login di Cognito
            Response.Redirect(loginUrl);
#endregion

        }
    }
}