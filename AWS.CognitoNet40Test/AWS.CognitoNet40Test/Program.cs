using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using JWT;
using JWT.Algorithms;
using JWT.Exceptions;
using JWT.Serializers;
using System;
using System.Collections.Generic;

public class Program
{
    private static readonly string userPoolId = "your-user-pool-id";
    private static readonly string clientId = "your-client-id";
    private static readonly string awsRegion = "your-region"; // e.g., us-east-1

    public static void Main(string[] args)
    {
        var provider = new AmazonCognitoIdentityProviderClient(Amazon.RegionEndpoint.USEast1);

        try
        {
            SignUpUser(provider, "username", "password", "email@example.com");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    public static void SignUpUser(AmazonCognitoIdentityProviderClient provider, string username, string password, string email)
    {
        var request = new SignUpRequest
        {
            ClientId = "your-client-id", // Replace with your Cognito user pool app client ID
            Username = username,
            Password = password,
            UserAttributes = new List<AttributeType>
            {
                new AttributeType
                {
                    Name = "email",
                    Value = email
                }
            }
        };

        SignUpResponse response = provider.SignUp(request);

        Console.WriteLine("User signed up successfully");
    }

    private static  void AuthenticateUser(AmazonCognitoIdentityProviderClient provider, string username, string password)
    {
        var authRequest = new InitiateAuthRequest
        {
            AuthFlow = AuthFlowType.USER_PASSWORD_AUTH,
            ClientId = clientId,
            AuthParameters = new Dictionary<string, string>
            {
                { "USERNAME", username },
                { "PASSWORD", password }
            }
        };

        try
        {
            var response = provider.InitiateAuth(authRequest);
            Console.WriteLine("User authenticated successfully. Token: " + response.AuthenticationResult.AccessToken);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error authenticating user: {ex.Message}");
        }
    }

    private static void Alloperation(AmazonCognitoIdentityProviderClient client)
    {
        var request = new AdminGetUserRequest
        {
            UserPoolId = "your-user-pool-id",
            Username = "username"
        };
        AdminGetUserResponse response = client.AdminGetUser(request);
        Console.WriteLine(response.Username);

        //
        var request2 = new AdminInitiateAuthRequest
        {
            UserPoolId = "your-user-pool-id",
            ClientId = "your-client-id",
            AuthFlow = AuthFlowType.ADMIN_NO_SRP_AUTH,
            AuthParameters = new Dictionary<string, string>
    {
        { "USERNAME", "username" },
        { "PASSWORD", "password" }
    }
        };
        AdminInitiateAuthResponse response2 = client.AdminInitiateAuth(request2);
        Console.WriteLine(response2.AuthenticationResult.IdToken);


        ///

        var request3 = new AdminRespondToAuthChallengeRequest
        {
            UserPoolId = "your-user-pool-id",
            ClientId = "your-client-id",
            ChallengeName = ChallengeNameType.NEW_PASSWORD_REQUIRED,
            ChallengeResponses = new Dictionary<string, string>
    {
        { "USERNAME", "username" },
        { "NEW_PASSWORD", "new-password" }
    },
            Session = "session-token"
        };
        AdminRespondToAuthChallengeResponse response3 = client.AdminRespondToAuthChallenge(request3);
        Console.WriteLine(response3.AuthenticationResult.IdToken);


        //
        var request4 = new AssociateSoftwareTokenRequest
        {
            AccessToken = "access-token"
        };
        AssociateSoftwareTokenResponse response4 = client.AssociateSoftwareToken(request4);
        Console.WriteLine(response4.SecretCode);

        //
        var request5 = new ListUsersRequest
        {
            UserPoolId = "your-user-pool-id"
        };
        ListUsersResponse response5 = client.ListUsers(request5);
        foreach (var user in response5.Users)
        {
            Console.WriteLine(user.Username);
        }




    }
}

public class JwtTokenValidator
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
