
using Domain.Entities;

namespace Application.Interfaces;

public interface ICurrentUserService 
{
  Task<bool> IsInRoleAsync(string role);
  Task<bool> IsInRoleAsync(string[] roles);

  Guid? GetUserId();
  Task<long?> GetLastPasswordUpdateDateAsync();
}