﻿namespace FamilySync.Services.Identity.Extensions;

public static class HttpResponseExtensions
{
    public static void AppendCookie(this HttpResponse response, string key, string refreshToken, DateTimeOffset? expiryDate, string path)
    {
        response.Cookies.Append(key, refreshToken, new()
        {
            SameSite = SameSiteMode.Strict,
            Secure = true,
            HttpOnly = true,
            Expires = expiryDate,
            Path = path,
            IsEssential = true
        });
    }
}