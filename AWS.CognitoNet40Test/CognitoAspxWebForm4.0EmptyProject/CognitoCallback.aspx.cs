using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using CognitoAspxWebForm4._0EmptyProject;
using JWT;
using JWT.Algorithms;
using JWT.Exceptions;
using JWT.Serializers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
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

        // Metodo per estrarre il "kid" dal header del token JWT
        static string GetKidFromToken(string token)
        {
            var parts = token.Split('.');
            var header = parts[0];
            var decodedHeader = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(PadBase64String(header)));
            var headerJson = JObject.Parse(decodedHeader);
            return headerJson["kid"].ToString();
        }

        // Metodo per aggiungere il padding al Base64 se necessario
        static string PadBase64String(string str)
        {
            return str.Length % 4 == 0 ? str : str + new string('=', 4 - str.Length % 4);
        }

        // Metodo per creare l'oggetto RSACryptoServiceProvider dalla chiave pubblica JWK
        //static RSACryptoServiceProvider CreateRsaProviderFromJwk(string modulus, string exponent)
        //{
        //    var rsa = new RSACryptoServiceProvider();
        //    var rsaParameters = new RSAParameters
        //    {
        //        Modulus = FromBase64Url(modulus),
        //        Exponent = FromBase64Url(exponent)
        //    };

        //    rsa.ImportParameters(rsaParameters);
        //    return rsa;
        //}

        // Converti Base64Url in byte array
        static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0 ? base64Url :
                            base64Url + new string('=', 4 - base64Url.Length % 4);
            string base64 = padded.Replace('-', '+').Replace('_', '/');
            return Convert.FromBase64String(base64);
        }

        static RSACryptoServiceProvider CreateRsaProviderFromJwk(string modulus, string exponent)
        {
            var rsa = new RSACryptoServiceProvider();
            var rsaParameters = new RSAParameters
            {
                Modulus = FromBase64Url(modulus),
                Exponent = FromBase64Url(exponent)
            };

            rsa.ImportParameters(rsaParameters);
            return rsa;
        }
        private static void TestTokenValidation()
        {
        // URL del file di configurazione OpenID Connect di Cognito
        string openidConfigUrl = "https://<your_cognito_domain>.auth.<region>.amazoncognito.com/.well-known/openid-configuration";

        // Inizializza la classe per ottenere il JWKS URI
        var jwksValidator = new JwtTokenValidatorWithCognitoJWKS();
        string jwksUri = jwksValidator.GetJwksUrl(openidConfigUrl);

        // Ottieni le chiavi dal JWKS URI
        var jwksKeys = jwksValidator.GetJwksKeys(jwksUri);


            // Il token JWT che devi validare
            string token = "<il_tuo_token_jwt>";

            // Estrai il "kid" dal header del token JWT
            string kid = GetKidFromToken(token);

            // Cerca la chiave pubblica corrispondente al "kid" nel JWKS
            var jwk = jwksKeys.FirstOrDefault(k => k["kid"].ToString() == kid);

            if (jwk != null)
            {
                // Estrai la chiave pubblica dal JWK
                string exponent = jwk["e"].ToString();
                string modulus = jwk["n"].ToString();

                // Converti la chiave pubblica in formato utilizzabile da RSA
                //var rsaProvider = CreateRsaProviderFromJwk(modulus, exponent);

                // Ottieni la chiave pubblica corretta (usa il codice precedentemente fornito per estrarre il "kid")
                RSACryptoServiceProvider rsaProvider = CreateRsaProviderFromJwk(modulus, exponent);

                // Inizializza il validatore JWT
                var jwtValidator = new CognitoAspxWebForm4._0EmptyProject.JwtTokenValidatorWithJWT();
                bool isValid = jwtValidator.ValidateToken(token, rsaProvider);

                Console.WriteLine("Token valido: " + isValid);

                Console.WriteLine("Token valido: " + isValid);
            }
            else
            {
                Console.WriteLine("Nessuna chiave trovata per il 'kid' specificato.");
            }
            //--------------------------


          
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

    public class JwtValidatorManuale
    {
        public bool ValidateToken(string token, string secret)
        {
            try
            {
                var parts = token.Split('.');
                if (parts.Length != 3)
                {
                    throw new ArgumentException("Token non valido");
                }

                var header = parts[0];
                var payload = parts[1];
                var signature = parts[2];

                var encodedHeaderAndPayload = $"{header}.{payload}";
                var secretKeyBytes = Encoding.UTF8.GetBytes(secret);
                var computedSignature = ComputeHMACSHA256(encodedHeaderAndPayload, secretKeyBytes);

                if (computedSignature != signature)
                {
                    Console.WriteLine("Firma del token non valida!");
                    return false;
                }

                Console.WriteLine("Token valido!");
                Console.WriteLine($"Payload: {Encoding.UTF8.GetString(Convert.FromBase64String(payload))}");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Errore durante la validazione del token: " + ex.Message);
                return false;
            }
        }

        private string ComputeHMACSHA256(string data, byte[] key)
        {
            using (var hmacsha256 = new HMACSHA256(key))
            {
                var hash = hmacsha256.ComputeHash(Encoding.UTF8.GetBytes(data));
                return Base64UrlEncode(hash);
            }
        }

        private string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Replace('+', '-').Replace('/', '_').Replace("=", "");
            return output;
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