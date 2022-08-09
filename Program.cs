using authServer;
using authServer.Data;
using authServer.Entities;
using authServer.Stores;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using OpenIddict.Abstractions;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;
var config = builder.Configuration;

services.AddControllers();
services.AddSwaggerGen(c => c.SwaggerDoc("v1", new OpenApiInfo { Title = "auth server", Version = "v1" }));

services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(config.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict();
});

services.Configure<IdentityOptions>(options =>
{
    options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Name;
    options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
    options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;
    // configure more options if necessary...
});

// OpenId Connect server configuration
services.AddOpenIddict()
.AddCore(options => options.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>())
.AddServer(options =>
{
    // Enable the required endpoints
    options.SetTokenEndpointUris("/connect/token");
    options.SetUserinfoEndpointUris("/connect/userinfo");

    options.AllowPasswordFlow();
    options.AllowRefreshTokenFlow();
    // Add all auth flows that you want to support
    // Supported flows are:
    //      - Authorization code flow
    //      - Client credentials flow
    //      - Device code flow
    //      - Implicit flow
    //      - Password flow
    //      - Refresh token flow

    // Custom auth flows are also supported
    options.AllowCustomFlow("custom_flow_name");

    // Using reference tokens means that the actual access and refresh tokens are stored in the database
    // and a token referencing the actual tokens (in the db) is used in the request header.
    // The actual tokens are not made public.
    options.UseReferenceAccessTokens();
    options.UseReferenceRefreshTokens();

    // Register your scopes
    // Scopes are a list of identifiers used to specify what access privileges are requested.
    options.RegisterScopes(OpenIddictConstants.Permissions.Scopes.Email,
                                OpenIddictConstants.Permissions.Scopes.Profile,
                                OpenIddictConstants.Permissions.Scopes.Roles);

    // Set the lifetime of your tokens
    options.SetAccessTokenLifetime(TimeSpan.FromMinutes(30));
    options.SetRefreshTokenLifetime(TimeSpan.FromDays(7));

    // Register signing and encryption details
    options.AddDevelopmentEncryptionCertificate()
                    .AddDevelopmentSigningCertificate();

    // Register ASP.NET Core host and configure options
    options.UseAspNetCore().EnableTokenEndpointPassthrough();
})
.AddValidation(options =>
{
    options.UseLocalServer();
    options.UseAspNetCore();
});

services.AddAuthentication(options =>
{
    options.DefaultScheme = OpenIddictConstants.Schemes.Bearer;
    options.DefaultChallengeScheme = OpenIddictConstants.Schemes.Bearer;
});

services.AddIdentity<User, Role>()
    .AddSignInManager()
    .AddUserStore<UserStore>()
    .AddRoleStore<RoleStore>()
    .AddUserManager<UserManager<User>>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

SeedData.Client(app);
SeedData.User(app);

app.Run();

