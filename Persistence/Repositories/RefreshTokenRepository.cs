using Domain.Entities;
using Domain.Interfaces;
using Microsoft.EntityFrameworkCore;
using Persistence.Data;

namespace Persistence.Repositories;

public class RefreshTokenRepository(
  AuthDbContext dbContext
) : IRefreshTokenRepository
{
    private readonly AuthDbContext _context = dbContext;

    public async Task<RefreshToken?> GetByTokenAsync(string token)
    {
        return await _context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == token);
    }

    public async Task<RefreshToken> CreateAsync(RefreshToken refreshToken)
    {
        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();
        return refreshToken;
    }

    public async Task<bool> UpdateAsync(RefreshToken refreshToken)
    {
        _context.RefreshTokens.Update(refreshToken);
        var result = await _context.SaveChangesAsync();

        return result > 0;
    }

    public async Task RevokeAsync(string token, string? revokedBy)
    {
        var refreshToken = await _context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == token);

        if (refreshToken != null)
        {
            refreshToken.Revoke(revokedBy ?? "system");
        }

        await _context.SaveChangesAsync();
    }

    public async Task RevokeAllUserTokensAsync(Guid userId, string? revokedBy)
    {
        var activeTokens = await _context.RefreshTokens
            .Where(rt => rt.UserId == userId && !rt.IsRevoked && rt.ExpiryDate > DateTime.UtcNow)
            .ToListAsync();

        foreach (var token in activeTokens)
        {
          token.Revoke(revokedBy ?? "system");
        }

        await _context.SaveChangesAsync();
    }

    public async Task<IEnumerable<RefreshToken>> GetActiveTokensByUserAsync(Guid userId)
    {
        return await _context.RefreshTokens
            .Where(rt => rt.UserId == userId && !rt.IsRevoked && rt.ExpiryDate > DateTime.UtcNow)
            .ToListAsync();
    }

    public async Task CleanupExpiredTokensAsync()
    {
        var expiredTokens = await _context.RefreshTokens
            .Where(rt => rt.ExpiryDate <= DateTime.UtcNow)
            .ToListAsync();
        if(expiredTokens.Count > 0)
        {
            _context.RefreshTokens.RemoveRange(expiredTokens);
            await _context.SaveChangesAsync();
        }
    }
}