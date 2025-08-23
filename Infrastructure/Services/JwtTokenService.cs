using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Application.Intefaces;
using Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Infrastructure.Services;

public class JwtTokenService(
  IConfiguration  config, 
  UserManager<ApplicationUser> userManager
) : IJwtTokenService
{
  private readonly IConfiguration _config = config;
  private readonly UserManager<ApplicationUser> _userManager = userManager;


  public async Task<string> GenerateAccessTokenAsync(ApplicationUser user)
  {
    var roles = await _userManager.GetRolesAsync(user);

    var claims = new List<Claim>
    {
      new (ClaimTypes.Name, user.UserName ?? ""),
      new (ClaimTypes.NameIdentifier, user.Id.ToString()),
      new (ClaimTypes.Email, user.Email ?? ""),
      new ("FirstName", user.FirstName ?? ""),
      new ("LastName", user.LastName ?? ""),
    };

    foreach (var role in roles)
    {
      claims.Add(new (ClaimTypes.Role, role));
    }
    
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtSettings:SecretKey"]!));
    var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
      issuer: _config["JwtSettings:Issuer"],
      audience: _config["JwtSettings:Audience"],
      claims: claims,
      expires: DateTime.UtcNow.AddMinutes(int.Parse(_config["JwtSettings:AccessTokenExpirationMinutes"]!)),
      signingCredentials: credentials
    );

    JwtSecurityTokenHandler tokenHandler = new();

    return tokenHandler.WriteToken(token);
  }

  public string GenerateRefreshToken()
  {
    var randomNumber = new byte[64];
    using var rng = RandomNumberGenerator.Create();
    rng.GetBytes(randomNumber);
    return Convert.ToBase64String(randomNumber);
  }

  public ClaimsPrincipal ValidateToken(string token)
  {
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.UTF8.GetBytes(_config["JwtSettings:SecretKey"]!);

    var tokenValidationParameters = new TokenValidationParameters
    {
      ValidateIssuer = true,
      ValidateAudience = true,
      ValidateLifetime = true,
      ValidateIssuerSigningKey = true,
      ValidIssuer = _config["JwtSettings:Issuer"],
      ValidAudience = _config["JwtSettings:Audience"],
      IssuerSigningKey = new SymmetricSecurityKey(key),
      ClockSkew = TimeSpan.Zero
    };
    try {
      var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
      if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
      {
        throw new SecurityTokenException("Invalid token");
      }
      return principal;
    } catch (Exception ex){
      throw new SecurityTokenException("Invalid token", ex);
    }
  }
}

