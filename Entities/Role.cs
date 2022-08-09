
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace authServer.Entities;

[Table(nameof(Role))]
public class Role : IdentityRole<long>
{
    public List<UserRole> UserRoles { get; set; } = null!;
}