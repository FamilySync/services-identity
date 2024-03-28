using Microsoft.EntityFrameworkCore;
namespace FamilySync.Services.Identity.Persistence;

public class IdentityContext : DbContext
{
    public DbSet<Models.Entities.Identity> Identities;

    public IdentityContext(DbContextOptions<IdentityContext> options) : base(options)
    {
    }
}