using Domain.Entities;

namespace Application.Interfaces;

public interface IRefreshTokenRepository
{
  Task<RefreshToken?> GetByTokenAsync(string token);
  Task<RefreshToken> CreateAsync(RefreshToken refreshToken);
  Task<bool> UpdateAsync(RefreshToken refreshToken);
  Task RevokeAsync(string token, string revokedBy);
  Task RevokeAllUserTokensAsync(Guid userId, string revokedBy);
  Task<IEnumerable<RefreshToken>> GetActiveTokensByUserAsync(Guid userId);
  Task CleanupExpiredTokensAsync();
}
