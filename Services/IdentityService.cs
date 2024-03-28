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
    Task<IdentityDTO> Get(Guid id);
    Task<IdentityResponse> Create(CreateIdentityRequest request);
}

public class IdentityService : IIdentityService
{
    private readonly IdentityContext _context;

    public IdentityService(IdentityContext context)
    {
        _context = context;
    }

    public async Task<IdentityDTO> Get(Guid id)
    {
        var entity = await _context.Identities.FirstOrDefaultAsync(x => x.Id == id);

        if (entity is null)
        {
            throw new NotFoundException(typeof(Models.Entities.Identity), id.ToString());
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