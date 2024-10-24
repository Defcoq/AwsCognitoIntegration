using JWT;
using JWT.Algorithms;
using JWT.Exceptions;
using JWT.Serializers;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace CognitoAspxWebForm4._0EmptyProject
{
    //public class JwtTokenValidatorWithJWT
    //{
    //    public bool ValidateToken(string token, RSACryptoServiceProvider rsaProvider)
    //    {
    //        try
    //        {
    //            // Estrai la chiave pubblica in formato PEM o byte array
    //            var publicKeyBytes = rsaProvider.ExportCspBlob(false); // Estrai la chiave pubblica

    //            // Configurazione del decoder JWT
    //            IJwtAlgorithm algorithm = new RS256Algorithm(rsaProvider, null); // Usa RS256 con la chiave pubblica
    //            IJsonSerializer serializer = new JsonNetSerializer();
    //            IDateTimeProvider provider = new UtcDateTimeProvider();
    //            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
    //            IJwtValidator validator = new JwtValidator(serializer, provider);
    //            IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);

    //            // Decodifica e verifica il token
    //            var payload = decoder.Decode(token, publicKeyBytes, verify: true); // Verifica con la chiave pubblica

    //            Console.WriteLine("Token valido! Payload: " + payload);

    //            return true;
    //        }
    //        catch (TokenExpiredException)
    //        {
    //            Console.WriteLine("Token scaduto!");
    //            return false;
    //        }
    //        catch (SignatureVerificationException)
    //        {
    //            Console.WriteLine("Firma del token non valida!");
    //            return false;
    //        }
    //        catch (Exception ex)
    //        {
    //            Console.WriteLine("Errore durante la validazione del token: " + ex.Message);
    //            return false;
    //        }
    //    }
    //}

    public class JwtTokenValidatorWithJWT
    {
        public bool ValidateToken(string token, RSACryptoServiceProvider rsaProvider)
        {
            try
            {
                // Usa l'algoritmo RS256 con la chiave pubblica
                IJwtAlgorithm algorithm = new RS256Algorithm(rsaProvider, null);
                IJsonSerializer serializer = new JsonNetSerializer();
                IDateTimeProvider provider = new UtcDateTimeProvider();
                IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                IJwtValidator validator = new JwtValidator(serializer, provider);
                IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);

                // Decodifica e verifica il token con la chiave pubblica
                var payload = decoder.Decode(token); // Verifica con la chiave pubblica

                Console.WriteLine("Token valido! Payload: " + payload);

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
}
