using FamilySync.Core.Persistence.Models;

namespace FamilySync.Services.Identity.Models.Entities;

public class RefreshToken : EntityBase<Guid>
{
    public Guid IdentityID { get; set; }
    public Guid UserID { get; set; }
    public DateTime ExpiryDate { get; set; }
    public string Token { get; set; } = default!;
}