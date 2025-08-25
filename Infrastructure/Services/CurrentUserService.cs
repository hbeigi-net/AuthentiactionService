

using System.Security.Claims;
using Application.Intefaces;
using Domain.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace Infrastructure.Services;

public class CurrentUserService(
  IHttpContextAccessor httpContextAccessor, 
  UserManager<ApplicationUser> userManager
) : ICurrentUserService
{
  private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
  private readonly UserManager <ApplicationUser>_userManger = userManager; 
  public Guid? GetUserId()
  { 
    var httpContext = _httpContextAccessor.HttpContext;
    if (httpContext is null) return null;

    var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    
    if(userId is null) return null;

    return Guid.Parse(userId);
  }

  public Task<bool> IsInRoleAsync(string role)
  {
    throw new NotImplementedException();
  }

  public Task<bool> IsInRoleAsync(string[] roles)
  {
    throw new NotImplementedException();
  }

  public async Task<long?> GetLastPasswordUpdateDateAsync() {
    var httpContext = _httpContextAccessor.HttpContext;
    var userClaims = httpContext?.User;
    var userId = userClaims?.FindFirstValue(ClaimTypes.NameIdentifier);

    if (string.IsNullOrEmpty(userId))
      return null;
      
    var user = await _userManger.FindByIdAsync(userId ?? ""); 

    if(user is null) return null;

    return user.PasswordUpdatedAt;
  }
}