using authServer.Data;
using authServer.Entities;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

namespace authServer;

public class SeedData
{
    public static async void Client(IApplicationBuilder app)
    {
        // Create OpenID Connect client application
        using var scope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        context.Database.EnsureCreated();

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var existingClientApp = manager.FindByClientIdAsync("default-client").GetAwaiter().GetResult();
        if (existingClientApp == null)
        {
           await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "default-client",
                ClientSecret = "499D56FA-B47B-5199-BA61-B298D431C318",
                DisplayName = "Default client application",
                Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddictConstants.Permissions.GrantTypes.Password
                    }
            });
        }
    }
    public static void User(IApplicationBuilder app)
    {
        using var scope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope();
        var user = new User
        {
            Username = "test_user",
            UserRoles = new List<UserRole>
                {
                    new UserRole { Role = new Role { Name = "admin", NormalizedName = "ADMIN" } }
                }
        };

        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
        var existingUser = userManager.FindByNameAsync(user.Username).GetAwaiter().GetResult();
        if (existingUser == null)
        {
            var hash = userManager.PasswordHasher.HashPassword(user, "Test1234!");
            user.PasswordHash = hash;
            userManager.CreateAsync(user).GetAwaiter().GetResult();
        }
    }
}