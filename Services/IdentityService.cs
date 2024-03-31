using FamilySync.Core.Helpers.Exceptions;
using FamilySync.Services.Identity.Models.DTO;
using FamilySync.Services.Identity.Models.Requests;
using FamilySync.Services.Identity.Models.Response;
using FamilySync.Services.Identity.Persistence;
using Mapster;
using Microsoft.EntityFrameworkCore;

namespace FamilySync.Services.Identity.Services;

public interface IIdentityService
{
    Task<IdentityDTO> Get(GetIdentityRequest request);
    Task<IdentityDTO> Get(Guid id);
    Task<IdentityDTO> GetByUsername(string username);
    Task<IdentityDTO> GetByEmail(string email);
    Task<IdentityResponse> Create(CreateIdentityRequest request);
}

public class IdentityService : IIdentityService
{
    private readonly IdentityContext _context;

    public IdentityService(IdentityContext context)
    {
        _context = context;
    }

    public async Task<IdentityDTO> Get(GetIdentityRequest request)
    {
        var entity = new Models.Entities.Identity();
        if (request.ID is not null)
        {
            entity = await _context.Identities.FirstOrDefaultAsync(x => x.ID == request.ID);
        }
        else if (request.Username is not null)
        {
            entity = await _context.Identities.FirstOrDefaultAsync(x => x.Username == request.Username);
        }
        else if (request.Email is not null)
        {
            entity = await _context.Identities.FirstOrDefaultAsync(x => x.Email == request.Email);
        }

        if (entity is null)
        {
            throw new NotFoundException("Failed to find Identity with provided information!");
        }

        var dto = entity.Adapt<IdentityDTO>();

        return dto;
    }

    public async Task<IdentityDTO> Get(Guid id)
    {
        var entity = await _context.Identities.FirstOrDefaultAsync(x => x.ID == id);

        if (entity is null)
        {
            throw new NotFoundException(typeof(Models.Entities.Identity), id.ToString());
        }

        var dto = entity.Adapt<IdentityDTO>();

        return dto;
    }

    public async Task<IdentityDTO> GetByUsername(string username)
    {
        var entity = await _context.Identities.FirstOrDefaultAsync(x => x.Username == username);

        if (entity is null)
        {
            throw new NotFoundException(typeof(Models.Entities.Identity), username);
        }

        var dto = entity.Adapt<IdentityDTO>();

        return dto;
    }

    public async Task<IdentityDTO> GetByEmail(string email)
    {
        var entity = await _context.Identities.FirstOrDefaultAsync(x => x.Email == email);

        if (entity is null)
        {
            throw new NotFoundException(typeof(Models.Entities.Identity), email);
        }

        var dto = entity.Adapt<IdentityDTO>();

        return dto;
    }

    public async Task<IdentityResponse> Create(CreateIdentityRequest request)
    {
        var entity = request.Adapt<Models.Entities.Identity>();

        _context.Identities.Add(entity);
        await _context.SaveChangesAsync();

        var response = entity.Adapt<IdentityResponse>();

        return response;
    }
}