using System;
using Domain.Entities;

namespace Domain.Interfaces;

public interface IApplicationUserRepository
{
  Task<ApplicationUser?> GetByIdAsync(Guid id);
  Task<ApplicationUser?> GetByEmailAsync(string email);
  Task<ApplicationUser?> GetByUsernameAsync(string username);
  Task<ApplicationUser?> GetByPhoneNumberAsync(string phoneNumber);
  Task<IQueryable<ApplicationUser>> GetAllAsync();
  Task<bool> CreateAsync(ApplicationUser user);
  Task<bool> CreateAsync(ApplicationUser user, string password);
  Task<bool> UpdateAsync(ApplicationUser user);
  Task<bool> DeleteAsync(Guid id);
  Task<bool> ExistsAsync(Guid id);
  Task<bool> IsEmailTakenAsync(string email, Guid? excludeUserId = null);
  Task<IEnumerable<string>> GetUserRolesAsync(Guid userId);
  Task<bool> IsInRoleAsync(Guid userId, string roleName);
  Task<bool> IsPhoneNumberTakenAsync(string phoneNumber, Guid? excludeUserId = null);
}
