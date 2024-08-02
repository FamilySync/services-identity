using FamilySync.Services.Identity.Models.DTOs;
using FamilySync.Services.Identity.Models.Requests.Identity;
using FamilySync.Services.Identity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FamilySync.Services.Identity.Controllers;

[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
public class IdentitiesController(IIdentityService identityService, ILogger<IdentitiesController> logger) : ControllerBase
{
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

            logger.LogError("Modelstate for IdentityCreate was not valid {errors}", errors);
            return BadRequest(ModelState);
        }

        var result = await identityService.Create(request);

        return CreatedAtAction(nameof(Get), new { id = result.Id }, result);
    }
    
    [HttpGet("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(IdentityDTO))]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<IdentityDTO>> Get([FromRoute] Guid id)
    {
        var result = await identityService.Get(id);
        
        return Ok(result);
    }
        
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [Authorize("familysync:admin")]
    public Task<ActionResult<string>> GetTest()
    {
        return Task.FromResult<ActionResult<string>>(Ok("Works"));
    }
}