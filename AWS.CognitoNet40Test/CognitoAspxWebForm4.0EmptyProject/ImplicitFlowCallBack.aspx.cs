using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace CognitoAspxWebForm4._0EmptyProject
{
    public partial class ImplicitFlowCallBack : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            #region con questo tipo di redirect da mettere nella pagina di reindirizzamento verso HOSTEDUI
            string clientId = "1example23456789";
            string domain = "mydomain";
            string region = "us-east-1";
            string redirectUri = "https://mydomain.example.com/CognitoCallback.aspx";

            // Reindirizza l'utente alla pagina di login di Cognito con il flusso implicito
            string loginUrl = string.Format(
                "https://{0}.auth.{1}.amazoncognito.com/authorize?response_type=token&client_id={2}&redirect_uri={3}&scope=openid+profile+aws.cognito.signin.user.admin",
                domain, region, clientId, HttpUtility.UrlEncode(redirectUri)
            );

            Response.Redirect(loginUrl);



            #endregion
            if (IsPostBack && Request.Form["access_token"] != null)
            {
                string accessToken = Request.Form["access_token"];
                string idToken = Request.Form["id_token"];

                // Usa l'access token come necessario (ad esempio, salvalo in una sessione)
                Session["AccessToken"] = accessToken;
                Session["IdToken"] = idToken;

                // Reindirizza l'utente alla pagina principale dopo il login
                Response.Redirect("HomePage.aspx");
            }
        }

        private void GetAccessToken(string authorizationCode)
        {
            string clientId = "tuo-client-id";
            string clientSecret = "tuo-client-secret";  // Inserisci il segreto del tuo client (opzionale, dipende dalla configurazione)
            string redirectUri = "https://tuo-dominio/CognitoCallback.aspx";
            string tokenEndpoint = $"https://tuo-dominio-cognito.auth.us-east-1.amazoncognito.com/oauth2/token";

            // Prepara la richiesta POST per scambiare il codice di autorizzazione con l'access token
            var postData = new NameValueCollection
    {
        { "grant_type", "authorization_code" },
        { "client_id", clientId },
        { "code", authorizationCode },
        { "redirect_uri", redirectUri }
    };

            using (WebClient client = new WebClient())
            {
                client.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";

                try
                {
                    byte[] responseBytes = client.UploadValues(tokenEndpoint, "POST", postData);
                    string responseBody = Encoding.UTF8.GetString(responseBytes);

                    // Parse the response JSON to get the access token
                    var json = JObject.Parse(responseBody);
                    string accessToken = json["access_token"].ToString();

                    // Salva o usa l'access token come necessario
                }
                catch (WebException ex)
                {
                    // Gestione errori
                    throw new ApplicationException("Errore durante la richiesta del token: " + ex.Message);
                }
            }
        }

    }
}