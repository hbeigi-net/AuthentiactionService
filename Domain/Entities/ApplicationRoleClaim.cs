using System;
using Microsoft.AspNetCore.Identity;

namespace Domain.Entities;

public class ApplicationRoleClaim : IdentityRoleClaim<Guid>
{
    public required virtual ApplicationRole Role { get; set; }
}