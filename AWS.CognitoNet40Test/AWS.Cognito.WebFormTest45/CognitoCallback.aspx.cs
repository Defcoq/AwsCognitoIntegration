using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using JWT;
using JWT.Algorithms;
using JWT.Exceptions;
using JWT.Serializers;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace AWS.Cognito.WebFormTest45
{
    public partial class CognitoCallback : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // Ottieni il codice di autorizzazione dalla query string
            string authorizationCode = Request.QueryString["code"];
            if (!string.IsNullOrEmpty(authorizationCode))
            {
                // Scambia il codice di autorizzazione con un access token
                ExchangeCodeForTokens(authorizationCode);
            }
            else
            {
                // Gestisci il caso in cui il codice non è presente o c'è un errore
                Response.Write("Error: Authorization code not found.");
            }

        }

        private void ExchangeCodeForTokens(string authorizationCode)
        {
            try
            {
                // Configura i parametri per ottenere i token da Cognito
                string clientId = "tuo-client-id";
                string clientSecret = "tuo-client-secret";
                string redirectUri = "https://tuo-dominio/CognitoCallback.aspx";
                string domain = "tuo-dominio-cognito";  // Es: "yourdomain.auth"
                string region = "your-region";  // Es: "us-east-1"

                // Fai la richiesta di token usando i parametri di autorizzazione
                var tokenEndpoint = $"https://{domain}.auth.{region}.amazoncognito.com/oauth2/token";

                using (var client = new System.Net.WebClient())
                {
                    var parameters = new NameValueCollection();
                    parameters.Add("grant_type", "authorization_code");
                    parameters.Add("client_id", clientId);
                    parameters.Add("code", authorizationCode);
                    parameters.Add("redirect_uri", redirectUri);
                    parameters.Add("client_secret", clientSecret);

                    // Imposta l'header per la richiesta
                    client.Headers.Add("Content-Type", "application/x-www-form-urlencoded");

                    // Richiedi il token
                    var response = client.UploadValues(tokenEndpoint, "POST", parameters);
                    string responseText = System.Text.Encoding.UTF8.GetString(response);

                    // Analizza la risposta (token) e salva la sessione dell'utente
                    // In questa fase puoi salvare il token JWT ricevuto e usarlo per gestire la sessione utente
                    Response.Write("Token response: " + responseText);
                }
            }
            catch (Exception ex)
            {
                Response.Write("Error exchanging code for tokens: " + ex.Message);
            }
        }
    }

    public class JwtTokenValidatorWithJWT
    {
        public bool ValidateToken(string token, string secretKey)
        {
            try
            {
                // Configurazione del decoder JWT
                IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // L'algoritmo usato per decodificare il token
                IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                IJsonSerializer serializer = new JsonNetSerializer();
                IDateTimeProvider provider = new UtcDateTimeProvider();
                IJwtValidator validator = new JwtValidator(serializer, provider);
                IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);

                // Decodifica e verifica il token
                var payload = decoder.Decode(token, secretKey, verify: true); // 'secretKey' è la chiave segreta usata da Cognito

                Console.WriteLine("Token valido! Payload: " + payload);

                // Qui puoi aggiungere ulteriori controlli sui claims del token (es: 'iss', 'aud', etc.)
                return true;
            }
            catch (TokenExpiredException)
            {
                Console.WriteLine("Token scaduto!");
                return false;
            }
            catch (SignatureVerificationException)
            {
                Console.WriteLine("Firma del token non valida!");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Errore durante la validazione del token: " + ex.Message);
                return false;
            }
        }
    }
        public class TokenValidator
        {
            public bool ValidateToken(string token)
            {
                var cognitoPoolId = "tuo-pool-id"; // Es. "us-east-1_abcdefgh"
                var cognitoIssuer = $"https://cognito-idp.your-region.amazonaws.com/{cognitoPoolId}";
                var jwksUrl = $"{cognitoIssuer}/.well-known/jwks.json";

                // Scarica le chiavi pubbliche JWKS da AWS Cognito
                var webClient = new WebClient();
                var jwksJson = webClient.DownloadString(jwksUrl);

                var jwks = new JsonWebKeySet(jwksJson);
                var tokenHandler = new JwtSecurityTokenHandler();

                // Imposta i parametri di validazione
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = cognitoIssuer,
                    ValidateAudience = true,
                    ValidAudience = "tuo-client-id", // Il client ID di Cognito
                    ValidateLifetime = true,
                    IssuerSigningKeys = jwks.Keys,  // Utilizza le chiavi JWKS per la validazione
                    ValidateIssuerSigningKey = true,
                };

                try
                {
                    // Tenta di validare il token
                    tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
                    return true; // Token valido
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Token validation failed: " + ex.Message);
                    return false; // Token non valido
                }
            }
        }

        public class CognitoLogout
        {
            private static readonly string clientId = "tuo-client-id"; // Il client ID della tua app Cognito
            private static readonly string accessToken = "access-token-dell-utente"; // L'access token dell'utente

            public static void GlobalLogout()
            {
                var cognitoClient = new AmazonCognitoIdentityProviderClient(Amazon.RegionEndpoint.USEast1);

                var globalSignOutRequest = new GlobalSignOutRequest
                {
                    AccessToken = accessToken // Fornisci l'access token dell'utente da disconnettere
                };

                try
                {
                    var response = cognitoClient.GlobalSignOut(globalSignOutRequest);
                    Console.WriteLine("Logout globale eseguito con successo.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Errore durante il logout globale: " + ex.Message);
                }
            }
        }

    public class CognitoUserInfo
    {
        public void GetUserInformation(string accessToken)
        {
            // Crea il client per comunicare con Cognito
            var cognitoClient = new AmazonCognitoIdentityProviderClient(Amazon.RegionEndpoint.APEast1);

            // Crea una richiesta GetUser con il token di accesso ottenuto dopo l'autenticazione
            var request = new GetUserRequest
            {
                AccessToken = accessToken
            };

            try
            {
                // Invia la richiesta a Cognito
                var response = cognitoClient.GetUser(request);

                // Recupera le informazioni dell'utente
                Console.WriteLine("Username: " + response.Username);

                foreach (var attribute in response.UserAttributes)
                {
                    Console.WriteLine($"{attribute.Name}: {attribute.Value}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Errore durante il recupero delle informazioni utente: " + ex.Message);
            }
        }
    }

}