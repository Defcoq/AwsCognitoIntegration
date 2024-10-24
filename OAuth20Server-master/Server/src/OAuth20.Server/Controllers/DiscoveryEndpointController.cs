/*
                        GNU GENERAL PUBLIC LICENSE
                          Version 3, 29 June 2007
 Copyright (C) 2022 Mohammed Ahmed Hussien babiker Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
 */

using Microsoft.AspNetCore.Mvc;
using OAuth20.Server.OauthResponse;
using IdentityModel;
using OAuth20.Server.Models;
using System.Collections.Generic;
using System.Linq;
using System;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;


namespace OAuth20.Server.Controllers
{
    public class DiscoveryEndpointController : Controller
    {
        // .well-known/openid-configuration
        [HttpGet("~/.well-known/openid-configuration")]
        public JsonResult GetConfiguration()
        {
            var test = OidcConstants.Discovery.AuthorizationEndpoint;
            var response = new DiscoveryResponse
            {
                issuer = "https://localhost:7275",
                authorization_endpoint = "https://localhost:7275/Home/Authorize",
                token_endpoint = "https://localhost:7275/Home/Token",
                token_endpoint_auth_methods_supported = new string[] { "client_secret_basic", "private_key_jwt" },
                token_endpoint_auth_signing_alg_values_supported = new string[] { "RS256", "ES256" },

                acr_values_supported = new string[] {"urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"},
                response_types_supported = new string[] { "code", "code id_token", "id_token", "token id_token" },
                subject_types_supported = new string[] { "public", "pairwise" },
                userinfo_endpoint = "https://localhost:7275/api/UserInfo/GetUserInfo",
                userinfo_encryption_enc_values_supported = new string[] { "A128CBC-HS256", "A128GCM" },
                id_token_signing_alg_values_supported = new string[] { "RS256", "ES256", "HS256" , "SHA256" },
                id_token_encryption_alg_values_supported = new string[] { "RSA1_5", "A128KW" },
                id_token_encryption_enc_values_supported = new string[] { "A128CBC-HS256", "A128GCM" },
                request_object_signing_alg_values_supported = new string[] { "none", "RS256", "ES256" },
                display_values_supported = new string[] { "page", "popup" },
                claim_types_supported = new string[] { "normal", "distributed" },
                jwks_uri = "https://localhost:7275/jwks.json",
                scopes_supported = new string[] { "openid", "profile", "email", "address", "phone", "offline_access" },
                claims_supported = new string[] { "sub", "iss", "auth_time", "acr", "name", "given_name",
                    "family_name", "nickname", "profile", "picture", "website", "email", "email_verified",
                    "locale", "zoneinfo" },
                claims_parameter_supported = true,
                service_documentation = "https://localhost:7275/connect/service_documentation.html",
                ui_locales_supported = new string[] { "en-US", "en-GB", "en-CA", "fr-FR", "fr-CA" },
                introspection_endpoint = "https://localhost:7275/Introspections/TokenIntrospect"

            };

            return Json(response);
        }

        // jwks.json
        [HttpGet("~/jwks.json")]
        public FileResult Jwks()
        {
            string path = "wwwroot/jwks.json";
            return File(path, System.Net.Mime.MediaTypeNames.Application.Json);
        }


        [HttpGet("~/jwks2.json")]
        public JsonResult GetJwks()
        {
            // Fetch all clients from your data source, where each client has a unique signing key
            var clients = GetAllClients(); // Method that retrieves all clients with their signing keys

            // Create a JWKS response with multiple keys, each with a unique kid
            var keys = clients.Select(client => new
            {
                kty = "oct", // "oct" means symmetric key
                use = "sig", // Use for signing
                kid = client.ClientId, // The Key ID (kid) is the client ID, which will help identify the key
                k = Convert.ToBase64String(Encoding.UTF8.GetBytes(client.SigninKey)) // Symmetric key
            });

            // Construct the JWKS response
            var jwks = new
            {
                keys = keys.ToArray() // The array of key sets
            };

            return Json(jwks); // Return the key set as a JSON result
        }



        public List<Client> GetAllClients()
        {
            // Create a list of fake clients for testing purposes
            return new List<Client>
        {
            new Client
            {
                ClientId = "client1",
                SigninKey = "client1-signing-key",
                TokenExpirySeconds = 3600,
                UseLocalDatetime = false,
                EncriptionKey = "client1-encryption-key"
            },
            new Client
            {
                ClientId = "client2",
                SigninKey = "client2-signing-key",
                TokenExpirySeconds = 7200,
                UseLocalDatetime = true,
                EncriptionKey = "client2-encryption-key"
            },
            new Client
            {
                ClientId = "client3",
                SigninKey = "client3-signing-key",
                TokenExpirySeconds = 1800,
                UseLocalDatetime = false,
                EncriptionKey = "client3-encryption-key"
            }
        };
        }


        public GenericResultTokenVM<AccessTokenCreationVM> CreateAccessToken(Client Audience, Client Issuer, ClaimsIdentity Claims, DateTime? ExpiresAt = null, DateTime? IssuedAtUtc = null)
        {
            // Create signing credentials using the client's signing key
            SigningCredentials credential = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Audience.SigninKey)),
                SecurityAlgorithms.HmacSha256Signature
            );

            DateTime _expiresAt = ExpiresAt ?? DateTime.UtcNow.AddSeconds(Audience.TokenExpirySeconds);
            DateTime _issuedAt = IssuedAtUtc ?? DateTime.UtcNow;

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            // Create the security token descriptor
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = Audience.ClientId,
                Expires = _expiresAt,
                Issuer = Issuer.ClientId,
                IssuedAt = _issuedAt,
                SigningCredentials = credential,
                Subject = Claims,
                // Add 'kid' to the JWT header so that Okta can match the token to the correct key in the JWKS
                AdditionalHeaderClaims = new Dictionary<string, object>
        {
            { "kid", Audience.ClientId } // Key ID (client's ID) is included in the token header
        }
            };

            if (!String.IsNullOrWhiteSpace(Audience.EncriptionKey))
            {
                tokenDescriptor.EncryptingCredentials = new EncryptingCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Audience.EncriptionKey)),
                    SecurityAlgorithms.HmacSha256Signature
                );
            }

            // Create the JWT token
            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);

            // Serialize the token to a string
            string strToken = tokenHandler.WriteToken(token);

            // Create and return the access token view model
            AccessTokenCreationVM result = new AccessTokenCreationVM
            {
                AccessToken = strToken,
                Issued = _issuedAt,
                Expiry = _expiresAt
            };

            return new GenericResultTokenVM<AccessTokenCreationVM>().Success1(result);
        }

        public GenericResultTokenVM<AccessTokenCreationVM> CreateAccessTokenWithRSA(Client Audience, Client Issuer, ClaimsIdentity Claims, RSA privateKey, DateTime? ExpiresAt = null, DateTime? IssuedAtUtc = null)
        {
            // Create signing credentials using the RSA private key
            var rsaKey = new RsaSecurityKey(privateKey); // Create an RSA key from the provided private key
            SigningCredentials credential = new SigningCredentials(
                rsaKey,
                SecurityAlgorithms.RsaSha256 // Use RSA SHA-256 for signing
            );

            DateTime _expiresAt = ExpiresAt ?? DateTime.UtcNow.AddSeconds(Audience.TokenExpirySeconds);
            DateTime _issuedAt = IssuedAtUtc ?? DateTime.UtcNow;

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            // Create the security token descriptor
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = Audience.ClientId,
                Expires = _expiresAt,
                Issuer = Issuer.ClientId,
                IssuedAt = _issuedAt,
                SigningCredentials = credential,
                Subject = Claims,
                // Add 'kid' to the JWT header so that Okta can match the token to the correct key in the JWKS
                AdditionalHeaderClaims = new Dictionary<string, object>
        {
            { "kid", Audience.ClientId } // Key ID (client's ID) is included in the token header
        }
            };

            // Create the JWT token
            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);

            // Serialize the token to a string
            string strToken = tokenHandler.WriteToken(token);

            // Create and return the access token view model
            AccessTokenCreationVM result = new AccessTokenCreationVM
            {
                AccessToken = strToken,
                Issued = _issuedAt,
                Expiry = _expiresAt
            };

            return new GenericResultTokenVM<AccessTokenCreationVM>().Success1(result);
        }

  

public static RSA CreateRsaKeyPair(int keySize = 2048)
    {
        using (var rsa = RSA.Create(keySize))
        {
            return rsa;
        }
    }


        public static string ExportPrivateKey(RSA rsa)
        {
            return Convert.ToBase64String(rsa.ExportRSAPrivateKey());
        }

        public static string ExportPublicKey(RSA rsa)
        {
            return Convert.ToBase64String(rsa.ExportRSAPublicKey());
        }

        public static RSA ImportPrivateKey(string privateKeyBase64)
        {
            var rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKeyBase64), out _);
            return rsa;
        }

        public static RSA ImportPublicKey(string publicKeyBase64)
        {
            var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKeyBase64), out _);
            return rsa;
        }

        public static void Usage()
        {
            //// Generate RSA Key Pair
            //RSA rsa = CreateRsaKeyPair();
            //string privateKey = ExportPrivateKey(rsa);
            //string publicKey = ExportPublicKey(rsa);

            //// Later, when creating the token
            //RSA signingKey = ImportPrivateKey(privateKey);
            //var token = CreateAccessTokenWithRSA(Audience, Issuer, Claims, signingKey);

            //// When verifying the token
            //RSA verifyingKey = ImportPublicKey(publicKey);
            //bool isValid = VerifyToken(token.AccessToken, verifyingKey);

        }



    }

    public class Client
    {
        public string ClientId { get; set; }        // Unique identifier for the client
        public string SigninKey { get; set; }       // The signing key used to sign tokens
        public int TokenExpirySeconds { get; set; } // How long the token is valid (in seconds)
        public bool UseLocalDatetime { get; set; }  // Whether to use local time or UTC
        public string EncriptionKey { get; set; }   // Optional encryption key for token encryption
    }


    public class AccessTokenCreationVM
    {
        public string AccessToken { get; set; } // The generated access token
        public DateTime Issued { get; set; }     // The date and time when the token was issued
        public DateTime Expiry { get; set; }      // The expiry date and time of the token
    }

    public class GenericResultTokenVM<T>
    {
        public bool Success { get; set; }         // Indicates whether the operation was successful
        public string ErrorMessage { get; set; }  // Holds error messages if the operation failed
        public T Data { get; set; }                // Holds the result data

        // Method to create a successful result
        public GenericResultTokenVM<T> Success1(T data)
        {
            this.Success = true;
            Data = data;
            return this;
        }

        // Method to create a failure result
        public GenericResultTokenVM<T> Failure(string errorMessage)
        {
            Success = false;
            ErrorMessage = errorMessage;
            return this;
        }
    }

}
