using System;
using Microsoft.AspNetCore.Identity;

namespace Domain.Entities;

public class ApplicationUserRole : IdentityUserRole<Guid>
{
  public DateTime AssignedAt { get; set; } = DateTime.UtcNow;
  public required string AssignedBy { get; set; }
  public required virtual ApplicationUser User { get; set; }
  public required virtual ApplicationRole Role { get; set; }
}
