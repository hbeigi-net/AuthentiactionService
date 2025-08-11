using System;
using Microsoft.AspNetCore.Identity;

namespace Domain.Entities;

public class ApplicationUserLogin : IdentityUserLogin<Guid>
{
    public virtual ApplicationUser? User { get; set; }
}
