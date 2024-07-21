namespace FamilySync.Services.Identity.Models.Requests.Identity;

public class Login
{
    public required string Email { get; set; }
    public required string Password { get; set; }
}