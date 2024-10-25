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
            #region   scenario chiamato interfaccia di login ospitata (Hosted UI) COGNITO https://docs.aws.amazon.com/cognito/latest/developerguide/login-endpoint.html
            // #region Reindirizzamento alla pagina di login ospitata di Cognito (Hosted UI) tramite GET /login

            string clientId = "ad398u21ijw3s9w3939";  // Inserisci il tuo client ID di Cognito
            string domain = "mydomain";  // Inserisci il dominio del tuo pool Cognito (es: "mydomain.auth")
            string region = "us-east-1";  // La tua regione AWS
            string redirectUri = "https://YOUR_APP/redirect_uri";  // La tua URL di callback
            string state = "some_random_state_value";  // Usato per mantenere lo stato durante il flusso di autorizzazione

            // Definisci lo scope richiesto
            string scope = "openid profile aws.cognito.signin.user.admin";

            // Costruisci l'URL di login utilizzando i parametri forniti
            string loginUrl = string.Format(
                "https://{0}.auth.{1}.amazoncognito.com/login?response_type=code&client_id={2}&redirect_uri={3}&state={4}&scope={5}",
                domain, region, clientId, HttpUtility.UrlEncode(redirectUri), HttpUtility.UrlEncode(state), HttpUtility.UrlEncode(scope)
            );

            // Esegui il reindirizzamento verso la pagina di login di Cognito
            Response.Redirect(loginUrl);

            // #endregion

            #endregion

            #region altro modo https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html
            // #region Reindirizzamento alla pagina di login ospitata di Cognito (Hosted UI)

            string clientId2 = "tuo-client-id";  // Inserisci il tuo client ID di Cognito
            string domain2 = "tuo-dominio-cognito";  // Il dominio di Cognito (es: "yourdomain.auth")
            string region2 = "your-region";  // La tua regione AWS (es: "us-east-1")
            string redirectUri2 = "https://tuo-dominio/CognitoCallback.aspx";  // La tua URL di callback

            // Parametri aggiuntivi per migliorare l'esperienza di login
            string responseType = "code";  // Otteniamo un authorization code (o token se preferito)
            string scope2 = "openid profile email";  // Richiesta di permessi per openid, profilo, email (modifica secondo le necessità)

            // Costruisci l'URL di login di Cognito con i parametri
            string loginUrl2 = string.Format(
                "https://{0}.auth.{1}.amazoncognito.com/login?response_type={2}&client_id={3}&redirect_uri={4}&scope={5}",
                domain2, region2, responseType, clientId2, HttpUtility.UrlEncode(redirectUri2), scope2
            );

            // Esegui il reindirizzamento verso la pagina di login di Cognito
            Response.Redirect(loginUrl);

            // #endregion

            #endregion
        }


        //https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html
        private void LogOutWithRedirectToCustomUrl()
        {
            // #region Reindirizzamento alla pagina di logout di Cognito con logout_uri

            string clientId = "1example23456789";  // Inserisci il tuo client ID di Cognito
            string domain = "mydomain";  // Inserisci il dominio del tuo pool Cognito (es: "mydomain.auth")
            string region = "us-east-1";  // La tua regione AWS
            string logoutUri = "https://www.example.com/welcome";  // La pagina a cui vuoi reindirizzare dopo il logout

            // Costruisci l'URL di logout utilizzando i parametri forniti
            string logoutUrl = string.Format(
                "https://{0}.auth.{1}.amazoncognito.com/logout?client_id={2}&logout_uri={3}",
                domain, region, clientId, HttpUtility.UrlEncode(logoutUri)
            );

            // Reindirizza l'utente alla pagina di logout di Cognito
            Response.Redirect(logoutUrl);

            // #endregion

        }

        private void LogOutWithRedirectToCognitoURL()
        {
            // #region Reindirizzamento alla pagina di logout di Cognito con redirect_uri

            string clientId = "1example23456789";  // Inserisci il tuo client ID di Cognito
            string domain = "mydomain";  // Inserisci il dominio del tuo pool Cognito (es: "mydomain.auth")
            string region = "us-east-1";  // La tua regione AWS
            string redirectUri = "https://www.example.com";  // La pagina di login a cui vuoi reindirizzare dopo il logout
            string state = "example-state-value";  // Mantieni lo stato durante il flusso di logout
            string scope = "openid profile aws.cognito.signin.user.admin";  // Ambiti richiesti

            // Costruisci l'URL di logout utilizzando i parametri forniti
            string logoutUrl = string.Format(
                "https://{0}.auth.{1}.amazoncognito.com/logout?response_type=code&client_id={2}&redirect_uri={3}&state={4}&scope={5}",
                domain, region, clientId, HttpUtility.UrlEncode(redirectUri), HttpUtility.UrlEncode(state), HttpUtility.UrlEncode(scope)
            );

            // Reindirizza l'utente alla pagina di logout di Cognito
            Response.Redirect(logoutUrl);

            // #endregion


        }
    }
}