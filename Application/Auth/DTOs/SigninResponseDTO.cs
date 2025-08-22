using System;

namespace Application.Auth.DTOs;

public class SigninResponseDTO
{
  public required string AccessToken { get; set; }
  public required string RefreshToken { get; set; }
}
