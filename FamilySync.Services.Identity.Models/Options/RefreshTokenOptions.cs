namespace FamilySync.Services.Identity.Models.Options;

public class RefreshTokenOptions
{
    public string CookieKey { get; set; } = default!;
    public float LifetimeInMinutes { get; set; }
}