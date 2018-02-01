

#r "bin/Release/net461/Google.Apis.Oauth2.v2.dll"
#r "bin/Release/net461/Google.Apis.Core.dll"
#r "bin/Release/net461/Google.Apis.Auth.dll"
#r "System.Net.Http"
#r "bin/Release/net461/GCP.IapTokenRequest.dll"

open Google.Apis.Auth.OAuth2
open System
open System.Net.Http.Headers

let SERVICEACCOUNT_JSON_PATH = Environment.GetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS")
let IAP_CLIENT_ID = "???"
let SAMPLE_APP_URL = sprintf "https://%s.appspot.com" "???"

//also can be read from oAuthClient secrets file 
//let oathClient = 
//    @"... path to secrets files ..."
//    |> File.OpenRead
//    |> GoogleClientSecrets.Load

let credential: ServiceAccountCredential = 
    downcast GoogleCredential.FromFile(SERVICEACCOUNT_JSON_PATH).UnderlyingCredential 

let token = credential.GetIapAccessTokenAsync(IAP_CLIENT_ID) |> Async.RunSynchronously

credential.HttpClient.DefaultRequestHeaders.Authorization <- AuthenticationHeaderValue("Bearer", token)
credential.HttpClient.GetStringAsync(SAMPLE_APP_URL).Result |> printfn "Result: %s"
 
