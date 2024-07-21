namespace FamilySync.Services.Identity.Models.Options;

public class AuthTokenConfig
{
    public static string Section = "AuthTokenConfig";

    public AccessTokenOptions AccessToken { get; set; } = new();
    public RefreshTokenOptions RefreshToken { get; set; } = new();
}