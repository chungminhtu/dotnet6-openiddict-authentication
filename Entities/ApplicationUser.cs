using Microsoft.AspNetCore.Identity;

namespace authServer.Entities;

public class ApplicationUser : IdentityUser<Guid>
{
    public ICollection<ApplicationUserRole> UserRoles { get; set; } = null!;
}