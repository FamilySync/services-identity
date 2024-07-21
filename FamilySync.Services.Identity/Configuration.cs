using FamilySync.Core.Abstractions;
using FamilySync.Core.Persistence.Extensions;
using FamilySync.Services.Identity.Models.Entities;
using FamilySync.Services.Identity.Models.Options;
using FamilySync.Services.Identity.Persistence;
using FamilySync.Services.Identity.Services;
using Microsoft.AspNetCore.Identity;

namespace FamilySync.Services.Identity;

public class Configuration : ServiceConfiguration
{
    public override void Configure(IApplicationBuilder builder)
    {
    }

    public override void ConfigureServices(IServiceCollection services)
    {
        // Persistence
        services.AddMySQLContext<IdentityContext>("identity", Configuration);
        
        // Options
        services.Configure<AuthTokenConfig>(Configuration.GetRequiredSection(AuthTokenConfig.Section));
        
        // Services
        services.AddIdentity<FamilySyncIdentity, IdentityRole<Guid>>()
            .AddEntityFrameworkStores<IdentityContext>()
            .AddDefaultTokenProviders();
        
        services.AddScoped<IIdentityService, IdentityService>();
        services.AddScoped<ITokenService, TokenService>();
        services.AddScoped<IEventPublisher, EventPublisher>();
    }
}