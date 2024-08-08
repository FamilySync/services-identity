namespace FamilySync.Services.Identity.Extensions;

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
    public static void DeleteCookie(this HttpResponse response, string key, string path)
    {
        response.Cookies.Delete(key, new()
        {
            SameSite = SameSiteMode.Strict,
            Secure = true,
            HttpOnly = true,
            Path = path,
            IsEssential = true
        });
    }
}