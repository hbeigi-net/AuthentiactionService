using System;
using Microsoft.AspNetCore.Identity;

namespace Domain.Entities;

public class ApplicationUserClaim : IdentityUserClaim<Guid>
{
    public virtual ApplicationUser? User { get; set; }
}