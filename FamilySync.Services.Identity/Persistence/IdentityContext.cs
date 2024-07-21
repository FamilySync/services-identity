using FamilySync.Services.Identity.Models.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FamilySync.Services.Identity.Persistence;

public class IdentityContext : IdentityDbContext<FamilySyncIdentity, IdentityRole<Guid>, Guid>
{
    public DbSet<FamilySyncIdentity> FamilySyncIdentities { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }

    public IdentityContext(DbContextOptions<IdentityContext> options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
    }
}