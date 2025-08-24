
using Domain.Entities;

namespace Application.Intefaces;

public interface ICurrentUserService 
{
  Task<bool> IsInRoleAsync(string role);
  Task<bool> IsInRoleAsync(string[] roles);

  Guid? GetUserId();
}