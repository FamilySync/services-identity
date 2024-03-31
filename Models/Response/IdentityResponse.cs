namespace FamilySync.Services.Identity.Models.Response;

public class IdentityResponse
{
    public Guid Id { get; set; }
    public string FullName { get; set; }
    public string Email { get; set; }
    public string Username { get; set; }
}