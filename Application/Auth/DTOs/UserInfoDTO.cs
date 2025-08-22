using System;

namespace Application.Auth.DTOs;

public class UserInfoDTO
{
  public Guid Id { get; set; }
  public string? FirstName { get; set; } = "";
  public string? LastName { get; set; } = "";
  public string FullName () => $"{FirstName} {LastName}";
  public required string Email { get; set; }
  public string? PhoneNumber { get; set; }
  public bool IsActive { get; set; }
  public DateTime? LastLoginAt { get; set; }
  public List<string> Roles { get; set; } = [];
  public DateTime CreatedAt { get; set; }
}
