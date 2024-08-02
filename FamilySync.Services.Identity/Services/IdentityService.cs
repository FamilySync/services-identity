using System.Security.Claims;
using FamilySync.Core.Abstractions.Exceptions;
using FamilySync.Core.Authentication.Claims;
using FamilySync.Services.Identity.Models.DTOs;
using FamilySync.Services.Identity.Models.Entities;
using FamilySync.Services.Identity.Models.Requests.Identity;
using Mapster;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.JsonWebTokens;

namespace FamilySync.Services.Identity.Services;

public interface IIdentityService
{
    public Task<IdentityDTO> Create(Create request);
    public Task<IdentityDTO> Get(Guid id);
    public Task<FamilySyncIdentity> Login(Login request);
}

public class IdentityService : IIdentityService
{
    private readonly UserManager<FamilySyncIdentity> _userManager;
    private readonly SignInManager<FamilySyncIdentity> _signInManager;
    private readonly ILogger<IdentityService> _logger;
    
    public IdentityService(UserManager<FamilySyncIdentity> userManager, ILogger<IdentityService> logger, SignInManager<FamilySyncIdentity> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
    }

    public async Task<IdentityDTO> Create(Create request)
    {
        var validator = new System.ComponentModel.DataAnnotations.EmailAddressAttribute();
        if (string.IsNullOrEmpty(request.Email) || !validator.IsValid(request.Email))
        {
            throw new BadRequestException($"Invalid email");
        }

        var entity = new FamilySyncIdentity
        {
            UserName = request.Username,
            Email = request.Email,
            UserID = Guid.NewGuid(),
            CreatedAt = request.CreatedAt,
            CreatedBy = request.CreatedBy!,
        };

        var result = await _userManager.CreateAsync(entity, request.Password);

        if (!result.Succeeded)
        {
            _logger.LogError("Failed creating identity with ID: {id} and email: {email}", entity.Id, entity.Email);
            throw new BadRequestException();
        }

        result = await AddDefaultClaims(entity);

        if (!result.Succeeded)
        {
            _logger.LogError("Failed while adding default claims, deleting identity with ID: {id}", entity.Id);

            await _userManager.DeleteAsync(entity);
            throw new BadRequestException();
        }

        _logger.LogInformation("Successfully created identity for {email}", entity.Email);

        var dto = entity.Adapt<IdentityDTO>();
        
        return dto;
    }

    public async Task<IdentityDTO> Get(Guid id)
    {
        var entity = await _userManager.FindByIdAsync(id.ToString());

        if (entity is null)
        {
            _logger.LogError("Failed to find {type} with id {id}", nameof(FamilySyncIdentity), id);
            throw new NotFoundException($"Failed to find {nameof(FamilySyncIdentity)} with íd {id}");
        }

        var dto = entity.Adapt<IdentityDTO>();

        return dto;
    }

    public async Task<FamilySyncIdentity> Login(Login request)
    {
        var entity = await _userManager.FindByEmailAsync(request.Email);
        
        if (entity is null)
        {
            _logger.LogError("Failed to find {type} with email: {email}", nameof(FamilySyncIdentity), request.Email);
            throw new NotFoundException($"Failed to find {typeof(FamilySyncIdentity)} with email: {request.Email}");
        }

        var signin = await _signInManager.CheckPasswordSignInAsync(entity, request.Password, true);
        
        // TODO: Customize requirements .. Such as Email confirmation, 2FA option etc

        if (signin.IsLockedOut)
        {
            throw new BadRequestException($"{typeof(FamilySyncIdentity)} with email: {request.Email} is locked out!");
        }

        if (!signin.Succeeded)
        {
            throw new BadRequestException($"Login failed");
        }

        return entity;
    }
    
    private async Task<IdentityResult> AddDefaultClaims(FamilySyncIdentity entity)
    {
        var claims = new List<Claim>()
        {
            new("iid", entity.Id.ToString()!),
            new("uid", entity.UserID.ToString()!),
            new(JwtRegisteredClaimNames.Sub, entity.UserName!),
            new(JwtRegisteredClaimNames.Email, entity.Email!),
            new("fs", Enum.GetName(ClaimLevel.Admin)!)
        };

        return await _userManager.AddClaimsAsync(entity, claims);
    }
}