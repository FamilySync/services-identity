namespace FamilySync.Services.Identity.Models.Requests;

public class GetIdentityRequest
{
    public Guid? ID { get; set; }
    public string? Username { get; set; }
    public string? Email { get; set; }
}