using FamilySync.Core.Helpers;
using FamilySync.Core.Persistence;
using FamilySync.Services.Identity.Persistence;
using FamilySync.Services.Identity.Services;

namespace FamilySync.Services.Identity;

public class Configuration : ServiceConfiguration
{
    public override void Configure(IApplicationBuilder app)
    {
        
    }

    public override void ConfigureServices(IServiceCollection services)
    {
        // Services
        services.AddTransient<IIdentityService, IdentityService>();
        
        // Persistence
        services.AddMySqlContext<IdentityContext>("identity", Configuration);
    }
}