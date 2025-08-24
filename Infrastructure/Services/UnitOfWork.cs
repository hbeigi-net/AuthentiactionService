using Domain.Entities;
using Domain.Interfaces;
using Infrastructure.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Storage;
using Persistence.Data;

namespace Persistence.Repositories;

public sealed class UnitOfWork(
    AuthDbContext dbContext,
    SignInManager<ApplicationUser> signInManager
  ) : IUnitOfWork
{
  private readonly AuthDbContext _context = dbContext;
  private readonly SignInManager<ApplicationUser> _signInManager = signInManager;
  private IDbContextTransaction? _transaction;

  public IApplicationUserRepository Users => new ApplicationUserRepository(_context, _signInManager.UserManager);

  public IRefreshTokenRepository RefreshTokens =>  new RefreshTokenRepository(_context);

  public SignInManager<ApplicationUser> SignInManager => _signInManager;

  public async Task BeginTransactionAsync()
  {
    _transaction = await _context.Database.BeginTransactionAsync();
  }

  public async Task CommitTransactionAsync()
  {
    if (_transaction is null) {
      throw new InvalidOperationException("Transaction is not started");
    };

    try
    {
      await _transaction.CommitAsync();
    }
    catch
    {
      await _transaction.RollbackAsync();
      throw;
    }
    finally
    {
      await _transaction.DisposeAsync();
      _transaction = null;
    }
  }

  public async Task RollbackTransactionAsync()
  {
    if (_transaction is null) {
      throw new InvalidOperationException("Transaction is not started");
    };

    try
    {
      await _transaction.RollbackAsync();
    }
    finally
    {
      await _transaction.DisposeAsync();
      _transaction = null;
    }
  }

  public async Task<int> SaveChangesAsync()
  {
    return await _context.SaveChangesAsync();
  }


  public async ValueTask DisposeAsync()
  {
    if (_transaction is not null)
    {
      await _transaction.DisposeAsync();
    }
      await _context.DisposeAsync();
  }
}