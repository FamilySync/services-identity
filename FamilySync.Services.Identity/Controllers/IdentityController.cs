using FamilySync.Services.Identity.Models.DTO;
using FamilySync.Services.Identity.Models.Requests;
using FamilySync.Services.Identity.Models.Response;
using FamilySync.Services.Identity.Services;
using Microsoft.AspNetCore.Mvc;

namespace FamilySync.Services.Identity.Controllers;

[Route("api/v{version:apiVersion}/[controller]")]
[ApiController]
public class IdentityController : ControllerBase
{
   private readonly IIdentityService _service;

   public IdentityController(IIdentityService service)
   {
      _service = service;
   }
   
   [HttpGet("Identity")]
   [ProducesResponseType(StatusCodes.Status404NotFound)]
   [ProducesResponseType(typeof(IdentityDTO), StatusCodes.Status200OK)]
   public async Task<ActionResult<IdentityDTO>> Get([FromQuery] GetIdentityRequest request)
   {
      var result = await _service.Get(request);

      return Ok(result);
   }
   
   [HttpPost]
   [ProducesResponseType(typeof(IdentityDTO), StatusCodes.Status201Created)]
   public async Task<ActionResult<IdentityDTO>> Post([FromBody] CreateIdentityRequest request)
   {
      var result = await _service.Create(request);

      return CreatedAtAction(nameof(Get), new { result.Id }, result);
   }
}