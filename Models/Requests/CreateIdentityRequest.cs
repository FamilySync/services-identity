namespace FamilySync.Services.Identity.Models.Requests;

public class CreateIdentityRequest
{
    public string FullName { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
}