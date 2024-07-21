using System.ComponentModel.DataAnnotations;
using FamilySync.Core.Persistence.Models.Requests;

namespace FamilySync.Services.Identity.Models.Requests.Identity;

public class Create : CreateRequestBase
{
    [EmailAddress] 
    public required string Email { get; set; } = default!;
    public required string Username { get; set; } = default!;
    public required string Password { get; set; } = default!;
}