using System;
using Domain.Common;

namespace Domain.Entities;

public class RefreshToken : IAuditableEntity
{
  public Guid Id { get; set; }
  public required string Token { get; set; }
  public DateTime ExpiryDate { get; set; }
  public bool IsRevoked { get; set; }
  public string? RevokedBy { get; set; }
  public DateTime? RevokedAt { get; set; }
  public string? ReplacedByToken { get; set; }
  public string? DeviceInfo { get; set; }
  public string? IpAddress { get; set; }

  public Guid UserId { get; set; }
  public ApplicationUser? User { get; set; }

  // Audit fields
  public DateTime CreatedAt { get; set; }
  public required string CreatedBy { get; set; }
  public DateTime? UpdatedAt { get; set; }
  public string? UpdatedBy { get; set; }

  public bool IsExpired => DateTime.Now > ExpiryDate;
  public bool IsActive => !IsRevoked && !IsExpired;

  public void Revoke(string revokedBy, string? replacedByToken = null)
  {
    IsRevoked = true;
    RevokedBy = revokedBy;
    RevokedAt = DateTime.UtcNow;
    ReplacedByToken = replacedByToken;
  }
}
