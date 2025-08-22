using System;
using Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace Domain.Interfaces;

public interface IUnitOfWork : IAsyncDisposable
{
    IApplicationUserRepository Users { get; }
    IRefreshTokenRepository RefreshTokens { get; }
    SignInManager<ApplicationUser> SignInManager { get; }
    Task<int> SaveChangesAsync();
    Task BeginTransactionAsync();
    Task CommitTransactionAsync();
    Task RollbackTransactionAsync();

}
