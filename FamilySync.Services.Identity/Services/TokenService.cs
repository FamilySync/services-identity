using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FamilySync.Core.Abstractions.Exceptions;
using FamilySync.Core.Abstractions.Options;
using FamilySync.Services.Identity.Models.DTOs;
using FamilySync.Services.Identity.Models.Entities;
using FamilySync.Services.Identity.Models.Options;
using FamilySync.Services.Identity.Persistence;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace FamilySync.Services.Identity.Services;

public interface ITokenService
{
    public Task<TokenDTO> Create(FamilySyncIdentity identity);
    Task Logout(HttpRequest request, HttpResponse response);
    Task<TokenDTO> Refresh(HttpRequest request);
}

public class TokenService : ITokenService
{
    private readonly IdentityContext _context;
    private readonly UserManager<FamilySyncIdentity> _userManager;
    private readonly SignInManager<FamilySyncIdentity> _signInManager;
    private readonly AuthTokenConfig _tokenConfig;
    private readonly ILogger<TokenService> _logger;
    private readonly AuthenticationOptions _authenticationOptions;
    private readonly IEventPublisher _eventPublisher;
    private readonly IOptionsMonitor<BearerTokenOptions> _bearerTokenOptions;

    private JwtSecurityTokenHandler _handler;
    private JwtSecurityTokenHandler Handler
    {
        get
        {
            return _handler ??= new();
        }
    }
    
    public TokenService(IdentityContext context, UserManager<FamilySyncIdentity> userManager, IOptions<AuthTokenConfig> tokenConfig,
        ILogger<TokenService> logger, IOptions<AuthenticationOptions> authenticationOptions, SignInManager<FamilySyncIdentity> signInManager, IEventPublisher eventPublisher, IOptionsMonitor<BearerTokenOptions> bearerTokenOptions)
    {
        _context = context;
        _userManager = userManager;
        _tokenConfig = tokenConfig.Value;
        _logger = logger;
        _signInManager = signInManager;
        _eventPublisher = eventPublisher;
        _bearerTokenOptions = bearerTokenOptions;
        _authenticationOptions = authenticationOptions.Value;
    }

    public async Task<TokenDTO> Create(FamilySyncIdentity identity)
    {
        var claims = await _userManager.GetClaimsAsync(identity);

        var accessToken = CreateToken(claims);
        var refreshToken = await CreateRefreshToken(identity.Id, identity.UserID);

        var expiresIn = (int)(accessToken.ValidTo - DateTime.UtcNow).TotalSeconds;

        return new TokenDTO
        (
            Handler.WriteToken(accessToken),
            refreshToken.Token,
            expiresIn,
            "Bearer",
            _tokenConfig.RefreshToken.CookieKey,
            refreshToken.ExpiryDate
        );
    }

    private JwtSecurityToken CreateToken(IList<Claim> claims)
    {
        var expires = DateTime.UtcNow.Add(TimeSpan.FromMinutes(_tokenConfig.AccessToken.LifeTimeInMinutes));
        var algoritm = "HS256";
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_authenticationOptions.Secret));
        var signingCredentials = new SigningCredentials(key, algoritm);

        return new(
            issuer: _authenticationOptions.Issuer,
            audience: _authenticationOptions.Audience,
            claims: claims,
            expires: expires,
            signingCredentials: signingCredentials
        );
    }

    public async Task<RefreshToken> CreateRefreshToken(Guid identityId, Guid userId)
    {
        var refreshLifeTime = TimeSpan.FromMinutes(_tokenConfig.RefreshToken.LifetimeInMinutes);

        var expiryDate = DateTime.UtcNow.Add(refreshLifeTime);

        var token = new RefreshToken
        {
            CreatedAt = DateTime.UtcNow,
            CreatedBy = "familysync.auth",
            IdentityID = identityId,
            UserID = userId,
            ExpiryDate = expiryDate,
            Token = Convert.ToBase64String(Guid.NewGuid().ToByteArray())
        };

        _context.RefreshTokens.Add(token);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Created RefreshToken for {id}", identityId);

        return token;
    }

    public async Task Logout(HttpRequest request, HttpResponse response)
    {
        var valid = request.Cookies.TryGetValue(_tokenConfig.RefreshToken.CookieKey, out var refreshToken);
        
        if (!valid)
        {
            return;
        }

        var token = await ConsumeRefreshToken(refreshToken!);

        if (token is not null)
        {
            await _eventPublisher.Logout(token.UserID);
        }
        
        response.Cookies.Delete(_tokenConfig.RefreshToken.CookieKey);
    }

    public async Task<TokenDTO> Refresh(HttpRequest request)
    {
        var valid = request.Cookies.TryGetValue(_tokenConfig.RefreshToken.CookieKey, out var refreshToken);
        
        if (!valid || string.IsNullOrEmpty(refreshToken)) 
            throw new UnauthorizedException();

        var token = await ConsumeRefreshToken(refreshToken);

        if (token is null) 
            throw new UnauthorizedException();
            
        var identity = await _userManager.FindByIdAsync(token.IdentityID.ToString());

        if (identity is null) 
            throw new UnauthorizedException();

        return await Create(identity);
    }

    private async Task<RefreshToken?> ConsumeRefreshToken(string token)
    {
        var refreshToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == token);

        if (refreshToken is null)
        {
            _logger.LogWarning("Attempted to consume RefreshToken {token} that doesn't exist!", token);
            return null;
        }

        _context.Remove(refreshToken);
        await _context.SaveChangesAsync();
        
        var expired = refreshToken.ExpiryDate < DateTime.UtcNow;
        
        if (expired)
        {
            _logger.LogInformation("Attempted to consume expired RefreshToken {token}", token);
            await _eventPublisher.Logout(refreshToken.IdentityID);
            return null;
        }
        
        var protector = _bearerTokenOptions.Get(IdentityConstants.BearerScheme).RefreshTokenProtector;
        var ticket = protector.Unprotect(refreshToken.Token);
        
        if (ticket == null)
        {
            _logger.LogWarning("Failed to unprotect RefreshToken {token}", token);
            return null;
        }
        
        // Make sure that if critical security-related information about the identity changes, it will not refresh your token, such as password.
        var validated = await _signInManager
            .ValidateSecurityStampAsync(ticket.Principal) != null;

        if (!validated)
        {
            _logger.LogInformation("Attempted to consume RefreshToken with invalid security stamp {token}", token);
            await _eventPublisher.Logout(refreshToken.IdentityID);
            return null;
        }
        
        _logger.LogInformation("Successfully Consumed RefreshToken {token}", token);

        return refreshToken;
    }
}