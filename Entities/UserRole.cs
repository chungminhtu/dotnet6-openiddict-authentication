
using System.ComponentModel.DataAnnotations.Schema;

namespace authServer.Entities;

[Table(nameof(UserRole))]
public class UserRole
{
    [ForeignKey(nameof(Entities.User.Id))]
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;

    [ForeignKey(nameof(Entities.Role.Id))]
    public long RoleId { get; set; }
    public Role Role { get; set; } = null!;
}