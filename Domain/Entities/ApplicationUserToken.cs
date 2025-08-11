using System;
using Microsoft.AspNetCore.Identity;

namespace Domain.Entities;

public class ApplicationUserToken : IdentityUserToken<Guid>
{
    public virtual ApplicationUser? User { get; set; }
}
