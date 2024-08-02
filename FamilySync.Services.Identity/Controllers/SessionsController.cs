using FamilySync.Services.Identity.Extensions;
using FamilySync.Services.Identity.Models.DTOs;
using FamilySync.Services.Identity.Models.Requests.Identity;
using FamilySync.Services.Identity.Services;
using Microsoft.AspNetCore.Mvc;

namespace FamilySync.Services.Identity.Controllers;

[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
public class SessionsController(IIdentityService identityService, ITokenService tokenService, ILogger<SessionsController> logger) : ControllerBase
{
    // TODO: I generally dont like mixing responsibilities across services / controllers. ex: DI IIdentityService & ITokenService .. Should look into facade pattern
    
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(AuthTokenDTO))]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<AuthTokenDTO>> Create([FromBody] Login request)
    {
        var entity = await identityService.Login(request);
        var token = await tokenService.Create(entity);

        Response.AppendCookie(token.CookieKey, token.RefreshToken, token.RefreshTokenExpiryDate, "/api/v1/sessions/current");

        logger.LogInformation("{email} successfully logged in!", request.Email);

        return Ok(token);
    }

    [HttpDelete("current")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<ActionResult> Delete()
    {
        await tokenService.Logout(Request, Response);

        return NoContent();
    }

    [HttpPut("current")]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(AuthTokenDTO))]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<AuthTokenDTO>> Update()
    {
        var token = await tokenService.Refresh(Request);

        Response.AppendCookie(token.CookieKey, token.RefreshToken, token.RefreshTokenExpiryDate, "/api/v1/sessions/current");

        return Ok(token);
    }
}