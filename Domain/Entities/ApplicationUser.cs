using System;
using Domain.Common;
using Microsoft.AspNetCore.Identity;

namespace Domain.Entities;

public class ApplicationUser : IdentityUser<Guid>, IAuditableEntity
{
  public string? FirstName { get; set; }
  public string? LastName { get; set; }
  public string FullName => $"{FirstName} {LastName}";
  public bool IsActive { get; set; } = true;
  public DateTime? LastLoginAt { get; set; }
  public string? ProfilePicture { get; set; }
  // Audit fields
  public DateTime CreatedAt { get; set; }
  public string? CreatedBy { get; set; } = "user";
  public DateTime? UpdatedAt { get; set; }
  public string? UpdatedBy { get; set; }
  public long PasswordUpdatedAt { get; set; }

  // Navigation properties 
  public virtual ICollection<ApplicationUserRole> UserRoles { get; set; } = new List<ApplicationUserRole>();
  public virtual ICollection<RefreshToken> ReferashTokens { get; set; } = [];

  public void UpdateProfile(string firstName, string lastName, string phoneNumber)
  {
    FirstName = firstName;
    LastName = lastName;
    PhoneNumber = phoneNumber;
    UpdatedAt = DateTime.UtcNow;
  }

  public void Activate()
  {
    IsActive = true;
    UpdatedAt = DateTime.UtcNow;
  }

  public void Deactivate()
  {
    IsActive = false;
    UpdatedAt = DateTime.UtcNow;
  }

  public void UpdateLastLogin()
  {
    LastLoginAt = DateTime.UtcNow;
  }
}
