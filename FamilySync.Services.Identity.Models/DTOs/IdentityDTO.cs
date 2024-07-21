namespace FamilySync.Services.Identity.Models.DTOs;

public class IdentityDTO
{
    public Guid Id { get; set; }
    public Guid? UserID { get; set; }
    public string Email { get; set; } = default!;
}