<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="ImplicitFlowCallBack.aspx.cs" Inherits="CognitoAspxWebForm4._0EmptyProject.ImplicitFlowCallBack" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
    <script type="text/javascript">
        window.onload = function () {
            // Estrai i parametri dal frammento URL
            const hash = window.location.hash.substring(1);  // Rimuove il '#'
            const params = new URLSearchParams(hash);
            const accessToken = params.get("access_token");
            const idToken = params.get("id_token");

            if (accessToken) {
                // Invio dei token al server
                var xhr = new XMLHttpRequest();
                xhr.open("POST", "CognitoCallback.aspx", true);
                xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                xhr.onreadystatechange = function () {
                    if (xhr.readyState === 4 && xhr.status === 200) {
                        // Lato client: token ricevuto correttamente dal server
                        console.log("Token inviato al server con successo.");
                    }
                };
                xhr.send("access_token=" + encodeURIComponent(accessToken) + "&id_token=" + encodeURIComponent(idToken));
            }
        };
    </script>
</head>
<body>
    <form id="form1" runat="server">
        <div>
              <h1>Elaborazione del login...</h1>
        </div>
    </form>
</body>
</html>
