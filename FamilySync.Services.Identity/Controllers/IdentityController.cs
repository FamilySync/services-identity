using FamilySync.Services.Identity.Extensions;
using FamilySync.Services.Identity.Models.DTOs;
using FamilySync.Services.Identity.Models.Requests.Identity;
using FamilySync.Services.Identity.Services;
using Microsoft.AspNetCore.Mvc;

namespace FamilySync.Services.Identity.Controllers;

[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
public class IdentityController : ControllerBase
{
    private readonly IIdentityService _identityService;
    private readonly ITokenService _tokenService;
    private readonly ILogger<IdentityController> _logger;

    public IdentityController(IIdentityService identityService, ILogger<IdentityController> logger, ITokenService tokenService)
    {
        _identityService = identityService;
        _logger = logger;
        _tokenService = tokenService;
    }

    [HttpPost]
    [ProducesResponseType(StatusCodes.Status201Created, Type = typeof(IdentityDTO))]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<IdentityDTO>> Create([FromBody] Create request)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState.Select(x => x.Value.Errors)
                .Where(y => y.Count > 0)
                .ToList();

            _logger.LogError("Modelstate for IdentityCreate was not valid {errors}", errors);
            return BadRequest(ModelState);
        }

        var result = await _identityService.Create(request);

        return CreatedAtAction(nameof(Get), new { id = result.Id }, result);
    }
    
    [HttpGet("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(IdentityDTO))]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<IdentityDTO>> Get([FromRoute] Guid id, CancellationToken cancellationToken)
    {
        var result = await _identityService.Get(id, cancellationToken);
        
        return Ok(result);
    }

    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(TokenDTO))]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<string> Login([FromBody] Login request)
    {
        var entity = await _identityService.Login(request);
        var token = await _tokenService.Create(entity);
        
        Response.AppendCookie(token.CookieKey, token.RefreshToken, token.RefreshTokenExpiryDate);
        
        return token.AccessToken;
    }

    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<ActionResult> Logout()
    {
        await _tokenService.Logout(Request, Response);

        return NoContent();
    }

    [HttpPost("refresh")]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(string))]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<string>> Refresh()
    {
        var token = await _tokenService.Refresh(Request);
        
        Response.AppendCookie(token.CookieKey, token.RefreshToken, token.RefreshTokenExpiryDate);

        return Ok(token.AccessToken);
    }
    

}