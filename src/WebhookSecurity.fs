namespace FunStripe

/// Module for verifying Stripe webhook signatures to prevent unauthorized webhook calls
/// See: https://stripe.com/docs/webhooks/signatures
module WebhookSecurity =
    
    open System
    open System.Security.Cryptography
    open System.Text
    
    /// Represents the result of webhook signature verification
    [<RequireQualifiedAccess>]
    type WebhookVerificationResult =
        | Valid
        | Invalid of reason: string
        | Error of error: string
    
    /// Stripe webhook signature header format: "t=timestamp,v1=signature1,v1=signature2,..."
    type StripeSignatureHeader = {
        Timestamp: int64
        Signatures: string list
    }
    
    /// Parses the Stripe-Signature header
    /// Format: "t=1492774577,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd,v1=..."
    let parseSignatureHeader (signatureHeader: string) : Result<StripeSignatureHeader, string> =
        try
            if String.IsNullOrWhiteSpace(signatureHeader) then
                Error "Signature header is empty"
            else
                let parts = signatureHeader.Split ','
                
                let timestampOpt =
                    parts
                    |> Array.tryFind (fun p -> p.StartsWith "t=")
                    |> Option.bind (fun t ->
                        let value = t.Substring 2
                        match Int64.TryParse value with
                        | true, ts -> Some ts
                        | false, _ -> None)
                
                let signatures =
                    parts
                    |> Array.filter (fun p -> p.StartsWith "v1=")
                    |> Array.map (fun s -> s.Substring 3)
                    |> Array.toList
                
                match timestampOpt with
                | Some timestamp when not (List.isEmpty signatures) ->
                    Ok { Timestamp = timestamp; Signatures = signatures }
                | Some _ ->
                    Error "No v1 signatures found in header"
                | None ->
                    Error "Invalid or missing timestamp in signature header"
        with ex ->
            Error $"Failed to parse signature header: {ex.Message}"
    
    /// Computes the expected signature for a webhook payload
    /// Formula: HMAC-SHA256(secret, timestamp.payload)
    let private computeSignature (webhookSecret: string) (timestamp: int64) (payload: string) : string =
        let signedPayload = $"{timestamp}.{payload}"
        let keyBytes = Encoding.UTF8.GetBytes webhookSecret
        let payloadBytes = Encoding.UTF8.GetBytes signedPayload
        
        use hmac = new HMACSHA256(keyBytes)
        let hashBytes = hmac.ComputeHash payloadBytes
        
        // Convert to lowercase hex string (Stripe format)
        hashBytes
        |> Array.map (fun b -> b.ToString "x2")
        |> String.concat ""
    
    /// Verifies a Stripe webhook signature with timing attack protection
    /// Uses constant-time comparison to prevent timing attacks
    let private secureCompare (signature1: string) (signature2: string) : bool =
        if signature1.Length <> signature2.Length then
            false
        else
            let mutable diff = 0
            for i in 0 .. signature1.Length - 1 do
                diff <- diff ||| (int signature1.[i] ^^^ int signature2.[i])
            diff = 0
    
    /// Verifies that a webhook is from Stripe and hasn't been tampered with
    /// 
    /// Parameters:
    ///   - webhookSecret: Your Stripe webhook secret (starts with "whsec_")
    ///   - signatureHeader: Value of the "Stripe-Signature" HTTP header
    ///   - payload: Raw webhook request body (must be the exact bytes received)
    ///   - toleranceSeconds: Max age of webhook in seconds (default: 300 = 5 minutes)
    ///
    /// Returns: WebhookVerificationResult indicating if the webhook is valid
    ///
    /// Example:
    ///   match WebhookSecurity.verifyWebhook webhookSecret signatureHeader requestBody 300L with
    ///   | Valid -> // Process webhook
    ///   | Invalid reason -> // Log and return 400
    ///   | Error err -> // Log error and return 500
    let verifyWebhook 
        (webhookSecret: string) 
        (signatureHeader: string) 
        (payload: string) 
        (toleranceSeconds: int64) : WebhookVerificationResult =
        
        try
            // Validate inputs
            if String.IsNullOrWhiteSpace webhookSecret then
                WebhookVerificationResult.Error "Webhook secret is required"
            elif not (webhookSecret.StartsWith "whsec_") then
                WebhookVerificationResult.Error "Invalid webhook secret format. Should start with 'whsec_'"
            elif String.IsNullOrWhiteSpace signatureHeader then
                WebhookVerificationResult.Invalid "Missing Stripe-Signature header"
            elif String.IsNullOrWhiteSpace payload then
                WebhookVerificationResult.Invalid "Empty webhook payload"
            else
                // Parse signature header
                match parseSignatureHeader signatureHeader with
                | Error reason ->
                    WebhookVerificationResult.Invalid $"Invalid signature header: {reason}"
                | Ok header ->
                    // Check timestamp is recent (replay attack prevention)
                    let currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                    let age = currentTimestamp - header.Timestamp
                    
                    if age > toleranceSeconds then
                        WebhookVerificationResult.Invalid $"Webhook timestamp too old. Age: {age}s, tolerance: {toleranceSeconds}s"
                    elif age < -toleranceSeconds then
                        WebhookVerificationResult.Invalid $"Webhook timestamp is in the future. Difference: {-age}s"
                    else
                        // Compute expected signature
                        let expectedSignature = computeSignature webhookSecret header.Timestamp payload
                        
                        // Check if any of the provided signatures match (Stripe can send multiple)
                        let isValid = 
                            header.Signatures
                            |> List.exists (fun sign -> secureCompare sign expectedSignature)
                        
                        if isValid then
                            WebhookVerificationResult.Valid
                        else
                            WebhookVerificationResult.Invalid "Signature verification failed. None of the provided signatures match."
        with ex ->
            WebhookVerificationResult.Error $"Unexpected error during webhook verification: {ex.Message}"
    
    /// Convenience function with default tolerance of 5 minutes (Stripe recommendation)
    let verifyWebhookDefault (webhookSecret: string) (signatureHeader: string) (payload: string) : WebhookVerificationResult =
        verifyWebhook webhookSecret signatureHeader payload 300L
    
    /// Helper function to safely handle webhook verification in a Result workflow
    let verifyWebhookResult 
        (webhookSecret: string) 
        (signatureHeader: string) 
        (payload: string) 
        (toleranceSeconds: int64) : Result<unit, string> =
        
        match verifyWebhook webhookSecret signatureHeader payload toleranceSeconds with
        | WebhookVerificationResult.Valid -> Ok ()
        | WebhookVerificationResult.Invalid reason -> Error $"Webhook verification failed: {reason}"
        | WebhookVerificationResult.Error err -> Error $"Webhook verification error: {err}"
    
    /// Example: ASP.NET Core middleware helper
    /// Usage in controller:
    ///   match WebhookSecurity.verifyFromRequest webhookSecret request with
    ///   | Ok payload -> // Process webhook with verified payload
    ///   | Error msg -> // Return BadRequest with error message
    let verifyFromRequest (webhookSecret: string) (request: Microsoft.AspNetCore.Http.HttpRequest) : Result<string, string> =
        async {
            try
                // Get signature header
                let signatureHeaderOpt = 
                    match request.Headers.TryGetValue "Stripe-Signature" with
                    | true, x -> Some (x.ToString())
                    | false, _ -> None
                
                match signatureHeaderOpt with
                | None ->
                    return Error "Missing Stripe-Signature header"
                | Some signatureHeader ->
                    // Read raw body (IMPORTANT: Must be raw bytes as received)
                    use reader = new System.IO.StreamReader(request.Body, Encoding.UTF8)
                    let! payload = reader.ReadToEndAsync() |> Async.AwaitTask
                    
                    // Verify signature
                    match verifyWebhookDefault webhookSecret signatureHeader payload with
                    | WebhookVerificationResult.Valid ->
                        return Ok payload
                    | WebhookVerificationResult.Invalid reason ->
                        return Error $"Invalid webhook: {reason}"
                    | WebhookVerificationResult.Error err ->
                        return Error $"Verification error: {err}"
            with ex ->
                return Error $"Failed to read webhook request: {ex.Message}"
        } |> Async.RunSynchronously

(*
// Example usage:
// https://stripe.com/docs/sources/best-practices
module WebhookExample =
    open System
    open WebhookSecurity
    open Microsoft.AspNetCore.Http
    
    // In your webhook handler:
    [<HttpPost("/webhook")>]
    let handleWebhook (webhookSecret: string) (request: HttpRequest) =
        match verifyFromRequest webhookSecret request with
        | Ok payload ->
            // Payload is verified - safe to process
            let event = Util.deserialise<StripeModel.Event> payload
            // Process event...
            // match event.Type with ...
            Results.Ok()
            // or this.Request.CreateResponse or whatever...
        | Error msg ->
            // Log the error (don't expose details to client)
            Logger.warn $"Webhook verification failed: {msg}"
            Results.BadRequest("Webhook signature verification failed")
    
    // Or manual verification:
    let verifyManually () =
        //this.Request.Headers.GetValues("Stripe-Signature")
        let secret = "whsec_test_secret"
        let signatureHeader = "t=1492774577,v1=5257a869..."
        let payload = """{"id":"evt_123","object":"event",...}"""
        
        match verifyWebhookDefault secret signatureHeader payload with
        | WebhookVerificationResult.Valid ->
            printfn "Webhook is valid!"
        | WebhookVerificationResult.Invalid reason ->
            printfn $"Invalid webhook: {reason}"
        | WebhookVerificationResult.Error err ->
            printfn $"Verification error: {err}"
*)
