namespace FamilySync.Services.Identity.Models.DTOs;

// TODO: Research if this record could exclude some props, like RefreshToken since this is only used for the cookie ..
public record AuthTokenDTO(string AccessToken, string RefreshToken, int ExpiresIn, string Type, string CookieKey, DateTime RefreshTokenExpiryDate);