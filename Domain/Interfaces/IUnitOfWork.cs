using System;

namespace Domain.Interfaces;

public interface IUnitOfWork : IDisposable
{
    IApplicationUserRepository Users { get; }
    IRefreshTokenRepository RefreshTokens { get; }
    Task<int> SaveChangesAsync();
    Task BeginTransactionAsync();
    Task CommitTransactionAsync();
    Task RollbackTransactionAsync();
}
