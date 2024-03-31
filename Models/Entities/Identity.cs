namespace FamilySync.Services.Identity.Models.Entities;

//TODO: This is VERY WIP .. Should use microsoft identity package to securely handle accounts / identities ..
// https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity?view=aspnetcore-8.0&tabs=visual-studio
public class Identity
{
    public Guid ID { get; set; }
    public string FullName { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
    public string Email { get; set; }
}