
using System.Security.Claims;
using Application.Intefaces;
using Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace Infrastructure.Services;

public class TokenValidator(
  UserManager<ApplicationUser> userManager
)
{
  public async Task<bool> ValidateAsync(ClaimsPrincipal claimsPrincipal)
  {

    var issuedAt = claimsPrincipal.FindFirstValue("IssuedAt");
    var userId = claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier);

    if (string.IsNullOrEmpty(userId))
      return false;

    var user = await userManager.FindByIdAsync(userId ?? "");
    
    if (user is null) return false;
    var PasswordUpdatedAt = user.PasswordUpdatedAt;
    if (long.TryParse(issuedAt, out var issuedAtUnix))
    {
      if (PasswordUpdatedAt > issuedAtUnix) return false;
    }

    return true;
  }
}