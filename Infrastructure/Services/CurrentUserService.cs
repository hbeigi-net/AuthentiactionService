

using System.Security.Claims;
using Application.Intefaces;
using Domain.Entities;
using Microsoft.AspNetCore.Http;

namespace Infrastructure.Services;

public class CurrentUserService(
  IHttpContextAccessor httpContextAccessor
) : ICurrentUserService
{
  private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

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

}