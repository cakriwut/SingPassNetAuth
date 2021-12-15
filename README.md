# SingPass .NET Authentication

The SingPass .NET Authentication project is an open-source and cross-platfrom implementation to provide __Log in with SingPass__ authentication in .NET application.




## Prerequisites
1. You'll need to install [NodeJS](https://nodejs.org/en/) and add the NodeJS executable to the `Path` environment variable.
2. You'll need to install npm package node-jose in the project folder.
3. You'll need to perform SingPass onboarding process, where you will exchange following:
    - `ClientJwks` , share either your app JWKS urls or manually created JWKS. Please note that SingPass prefer EC key type. (Responsibility: You/Application Owner)
    - `RedirectUrl`, share one or more redirect urls for SingPass authentication. Default: /signin-singpass. (Responsibility: You/Application Owner)
    - `ClientId`  , after the onboarding SingPass will provide ClientId. (Responsibility: SingPass)


## Getting Started
1. Install Package  
   Using Package Manager:
   ```
   PM> Install-Package SingPassNetAuth
   ```
   Using .NET CLI:
   ```
   > dotnet add-package SingPassNetAuth
   ```

2. Add Authentication in the `Startup.cs` 
   ```cs
   public void ConfigureServices(IServiceCollection services)
   {
       ...other contents...
       // Refer to SingPass API documentation - https://stg-id.singpass.gov.sg/docs/authorization/api#_staging_and_production_urls

       services.AddAuthentication()
          .AddSingPass(options => {
                    options.Authority = "";
                    options.ClientId = "";
                    options.ClientJwks = "";
          })

      ...other contents...
   }

## Target Frameworks
- .NET Standard 2.0
- .NET Framework 4.6.1
- .NET Core 3.1 

## Platforms
- Windows
- Linux

## References
1.  [Login with SingPass](https://api.singpass.gov.sg/library/login/developers/overview-at-a-glance) 
2.  [NDI Authentication Service Provider](https://stg-id.singpass.gov.sg/docs/authorization/api)

## How to Engage, Contribute, and Give Feedback 

__Need help or wanna share your thoughts?__ Don't hesitate to create issue, or pull request.

## License
This project is licensed under the __MIT License__.