
using Domain.Entities;
using Domain.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Persistence.Data;

namespace Persistence.Repositories;
public class ApplicationUserRepository(
  AuthDbContext dbContext,
  UserManager<ApplicationUser> userManager
) : IApplicationUserRepository
{
  private readonly AuthDbContext _dbContext = dbContext;
  private readonly UserManager<ApplicationUser> _userManager = userManager;

  public async Task<ApplicationUser?> GetByIdAsync(Guid id)
  {
    return await _userManager.FindByIdAsync(id.ToString());
  }
  public async Task<ApplicationUser?> GetByEmailAsync(string email)
  {
    return await _userManager.FindByEmailAsync(email);
  }
  public async Task<ApplicationUser?> GetByUsernameAsync(string username) 
  {
    return await _userManager.FindByNameAsync(username);
  }
  public Task<IQueryable<ApplicationUser>> GetAllAsync()
  {
    return Task.FromResult(_userManager.Users.AsQueryable());
  }

  public async Task<bool> CreateAsync(ApplicationUser user)
  {
    var result = await _userManager.CreateAsync(user);
    return result.Succeeded;
  }
  public async Task<bool> CreateAsync(ApplicationUser user, string password)
  {
    var result = await _userManager.CreateAsync(user, password);

    return result.Succeeded;
  }

  public async Task<bool> UpdateAsync(ApplicationUser user)
  {
    var result = await _userManager.UpdateAsync(user);
    return result.Succeeded;
  }

  public async Task<bool> DeleteAsync(Guid id)
  {
    var user = await _userManager.FindByIdAsync(id.ToString());
    if (user == null)
    {
      return false;
    }
    
    user.IsActive = false;
     var result = await _userManager.UpdateAsync(user);

    return result.Succeeded;
  }
  public async Task<bool> ExistsAsync(Guid id)
  {
    var user = await _userManager.FindByIdAsync(id.ToString());
    
    return user != null;
  }

  public async Task<bool> IsEmailTakenAsync(string email, Guid? excludeUserId = null) 
  {
    var isEmailTaken = await _userManager.Users.AnyAsync(usr => usr.Email == email && usr.Id != excludeUserId);
    
    return isEmailTaken;
  }

  public async Task<IEnumerable<string>> GetUserRolesAsync(Guid id) 
  {
    var user = await _userManager.FindByIdAsync(id.ToString());

    if(user is null){
      return Enumerable.Empty<string>();
    }

    return await _userManager.GetRolesAsync(user);
  }

  public async Task<bool> IsInRoleAsync(Guid id, string roleName)
  {
    var user = await _userManager.FindByIdAsync(id.ToString());
    if(user is null) {
      return false;
    }

    return await _userManager.IsInRoleAsync(user, roleName);
  }

  public async Task<bool> IsPhoneNumberTakenAsync(string phoneNumber, Guid? excludeUserId = null)
  {
    return await _userManager.Users.AnyAsync(usr => usr.PhoneNumber == phoneNumber && usr.Id != excludeUserId);
  }
  public async Task<ApplicationUser?> GetByPhoneNumberAsync(string phoneNumber)
  {
    return await _userManager.Users.FirstOrDefaultAsync(usr => usr.PhoneNumber == phoneNumber);
  }
}