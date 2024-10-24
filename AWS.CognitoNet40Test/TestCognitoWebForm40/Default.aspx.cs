using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace TestCognitoWebForm40
{
    public partial class _Default : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
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