using FamilySync.Services.Identity.Extensions;
using FamilySync.Services.Identity.Models.DTOs;
using FamilySync.Services.Identity.Models.Options;
using FamilySync.Services.Identity.Models.Requests.Identity;
using FamilySync.Services.Identity.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace FamilySync.Services.Identity.Controllers;

[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
public class SessionsController : ControllerBase
{
    private readonly IIdentityService _identityService;
    private readonly ITokenService _tokenService;
    private readonly ILogger<SessionsController> _logger;
    private readonly AuthTokenConfigOptions _tokenConfig;

    public SessionsController(IIdentityService identityService, ITokenService tokenService, ILogger<SessionsController> logger, IOptions<AuthTokenConfigOptions> tokenConfig)
    {
        _identityService = identityService;
        _tokenService = tokenService;
        _logger = logger;
        _tokenConfig = tokenConfig.Value;
    }

    // TODO: I generally dont like mixing responsibilities across services / controllers. ex: DI I_identityService & I_tokenService .. Should look into facade pattern
    
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(AuthTokenDTO))]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<AuthTokenDTO>> Create([FromBody] Login request)
    {
        var entity = await _identityService.Login(request);
        var token = await _tokenService.Create(entity);

        Response.AppendCookie(token.CookieKey, token.RefreshToken, token.RefreshTokenExpiryDate, "/api/v1/sessions/current");

        _logger.LogInformation("{email} successfully logged in!", request.Email);

        return Ok(token);
    }

    [HttpDelete("current")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<ActionResult> Delete()
    {
        await _tokenService.Logout(Request, Response);

        Response.DeleteCookie(_tokenConfig.RefreshToken.CookieKey, "/api/v1/sessions/current");
        
        return NoContent();
    }

    [HttpPut("current")]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(AuthTokenDTO))]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<AuthTokenDTO>> Update()
    {
        var token = await _tokenService.Refresh(Request);

        Response.AppendCookie(token.CookieKey, token.RefreshToken, token.RefreshTokenExpiryDate, "/api/v1/sessions/current");

        return Ok(token);
    }
}