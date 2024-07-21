namespace FamilySync.Services.Identity.Models.DTOs;

public record TokenDTO(string AccessToken, string RefreshToken, int ExpiresIn, string Type, string CookieKey, DateTime RefreshTokenExpiryDate);