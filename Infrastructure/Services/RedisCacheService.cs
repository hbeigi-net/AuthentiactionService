
using System.Text.Json;
using Application.Interfaces;
using StackExchange.Redis;

namespace Infrastructure.Services;

public class RedisCacheService(
  IConnectionMultiplexer connection
) : ICacheService
{
  private readonly IDatabase _db = connection.GetDatabase();

  public async Task<T?> GetAsync<T>(string key)
  {
    var value = await _db.StringGetAsync(key);
    return value.HasValue ? JsonSerializer.Deserialize<T>(value!) : default!;
  }

  public Task<bool> RemoveAsync(string key)
  {
    return _db.KeyDeleteAsync(key);
  }
  public async Task<bool> SetAsync<T>(string key, T value, TimeSpan? expiry = null)
  {
        return await _db.StringSetAsync(key, JsonSerializer.Serialize(value), expiry, When.Always, CommandFlags.None);
  }
}
