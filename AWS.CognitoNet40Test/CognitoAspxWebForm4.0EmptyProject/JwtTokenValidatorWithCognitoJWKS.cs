
using System;
using System.Net;
using Newtonsoft.Json.Linq;

namespace CognitoAspxWebForm4._0EmptyProject
{
    public class JwtTokenValidatorWithCognitoJWKS
    {
        public string GetJwksUrl(string openidConfigUrl)
        {
            using (var client = new WebClient())
            {
                // Ottieni la configurazione OpenID Connect
                var configJson = client.DownloadString(openidConfigUrl);
                var config = JObject.Parse(configJson);

                // Ottieni l'URI JWKS dal campo 'jwks_uri'
                string jwksUri = config["jwks_uri"].ToString();
                return jwksUri;
            }
        }

        public JToken GetJwksKeys(string jwksUri)
        {
            using (var client = new WebClient())
            {
                // Scarica le chiavi JWKS
                var jwksJson = client.DownloadString(jwksUri);
                var jwks = JObject.Parse(jwksJson);
                return jwks["keys"];
            }
        }
    }
}




