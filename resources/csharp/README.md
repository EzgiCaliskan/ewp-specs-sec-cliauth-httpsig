# Authenticating Clients with HTTP Signature

The document describes how to implement server authentication with Http Signature in C#.

Requirements:
- .Net Framework 5.0 (Core)
- Serilog.AspNetCore Version=4.1.0 
- Serilog.Extensions.Logging.File Version=2.0.0 
- Serilog.Settings.Configuration Version=3.3.0 
- Serilog.Sinks.File Version=5.0.0 
- Microsoft.Extensions.Configuration Version=6.0.1 

## How to use given codes

Codes given verifies the request by logging the details. For logging, Serilog is used. Install the serilog and the configuration packages from nuget into your project then insert the code into your startup.cs. 
````c
 public IConfiguration Configuration { get; }
 public Startup(IConfiguration configuration)
        {
            var path = Directory.GetCurrentDirectory();
            string logPath = ($"{path}\\Logs\\Log.txt");


            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Information()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
                .WriteTo.File(logPath, rollingInterval: RollingInterval.Day)
                .WriteTo.Console()
                .CreateLogger();

        }
````
Now the logs can be written into Logs directory in your project's directory.

Verifiying [the required headers](https://github.com/erasmus-without-paper/ewp-specs-sec-cliauth-httpsig#verify-authentication-method-used) is done in RequestValidator class with the help of these classes:
- HeaderParser.cs : Parses the request header then returns AuthRequest object. After that all the controls are done using it.
- BodyReader.cs : Reads the body content of the request
- RsaHelper.cs : Computes digest and verifies the signature of client.
- RegistryService.cs : Downloads catalog file from EWP Registry API and searches keyIds and certificates from catalog file. to download the file you need to add HttpSig attributes into appsettings.json

````
"HttpSig": {
    "CatalogFilePath": "C:\\EWP Files\\catalog.xml",
    "Servers": [
      {
        "HeiId": "iyte.edu.tr",
        "KeyId": "*** key id in catalog file ***",
        "PublicKey": [
          "**",
          "Insert private key lines as string array",
          "**",
          "**"
        ],
        "PrivateKey": [
          "**",
          "Insert private key lines as string array",
          "**",
          "**"
        ]
      }
    ]
  }
````

Verification performed in HttpContextFilter. Therefore, you need to add it to project filters on startup.cs as shown below:
````c
        services.AddControllers(config =>
            {
                config.Filters.Add(new HttpContextFilter());
            });
````

Important note: Replace "iyte.edu.tr" with your institution's heiId
Reach the whole project on [SUDTE/ewp-csharp-apis](https://github.com/SUDTE/ewp-csharp-apis)
