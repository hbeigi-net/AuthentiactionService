using System;
using Domain.Common;
using Microsoft.AspNetCore.Identity;

namespace Domain.Entities;

public class ApplicationRole : IdentityRole<Guid>, IAuditableEntity
{
  public string? Description { get; set; }
  public bool IsSystemRole { get; set; }
  public DateTime CreatedAt { get; set; }
  public required string CreatedBy { get; set; }
  public DateTime? UpdatedAt { get; set; }
  public string? UpdatedBy { get; set; }

  public virtual ICollection<ApplicationUserRole> UserRoles { get; set; } = new List<ApplicationUserRole>();
  public virtual ICollection<ApplicationRoleClaim> RoleClaims { get; set; } = [];

  public ApplicationRole() { }

  public ApplicationRole(string roleName, string? description = null)
  : base(roleName)
  {
    Description = description;
    CreatedAt = DateTime.UtcNow;
  }

}