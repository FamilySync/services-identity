using FamilySync.Core.Persistence.Models;
using Microsoft.AspNetCore.Identity;

namespace FamilySync.Services.Identity.Models.Entities;

public class FamilySyncIdentity : IdentityUser<Guid>, IEntityBase
{
    /// <summary>
    /// While IdentityUser provides an ID this is for the internal (Identity) System.
    /// While UserID provides an ID for external systems and communication.
    /// </summary>
    public Guid UserID { get; set; }
    
    // IEntityBase
    public DateTime? CreatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public string? UpdatedBy { get; set; }
}