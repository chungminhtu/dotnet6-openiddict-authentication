
using Microsoft.AspNetCore.Identity;

namespace authServer.Entities;

public class ApplicationRole : IdentityRole<Guid>
{
    public ICollection<ApplicationUserRole> UserRoles { get; set; } = null!;
}