using Microsoft.EntityFrameworkCore;
namespace FamilySync.Services.Identity.Persistence;

public class IdentityContext : DbContext
{
    public DbSet<Models.Entities.Identity> Identities { get; set; }

    public IdentityContext(DbContextOptions<IdentityContext> options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Models.Entities.Identity>()
            .HasIndex(x => x.Email)
            .IsUnique();

        modelBuilder.Entity<Models.Entities.Identity>()
            .HasIndex(x => x.Username)
            .IsUnique();
    }
}