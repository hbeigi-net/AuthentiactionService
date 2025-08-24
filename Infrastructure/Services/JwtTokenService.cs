using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Application.Intefaces;
using Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Infrastructure.Services;

public class JwtTokenService(
  IConfiguration config,
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
      claims.Add(new(ClaimTypes.Role, role));
    }

    var secretKey = _config["JwtSettings:SecretKey"]!;
    var expirationMinutes = int.Parse(_config["JwtSettings:AccessTokenExpirationMinutes"]!);

    var token = _signToken(secretKey, claims, expirationMinutes);

    return token;
  }

  public string GenerateRefreshToken(ApplicationUser user)
  {
    List<Claim> claims = new () {
      new (ClaimTypes.NameIdentifier, user.Id.ToString()),
    };
    var expirationMinutes = int.Parse(_config["JwtSettings:RefreshTokenSecretKeyExpirationMinutes"]!);
    var secretKey = _config["JwtSettings:RefreshTokenSecretKey"]!;

    var token = _signToken(secretKey, claims, expirationMinutes);

    return token;
  }

  private string _signToken(
    string secretKey,
    List<Claim> claims,
    int expirationMinutes
  )
  {
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
    var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
      issuer: _config["JwtSettings:Issuer"],
      audience: _config["JwtSettings:Audience"],
      claims: claims,
      expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
      signingCredentials: credentials
    );

    var tokenHandler = new JwtSecurityTokenHandler();

    return tokenHandler.WriteToken(token);
  }

  public ClaimsPrincipal? ValidateToken(string token, string secretKey)
  {
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.UTF8.GetBytes(secretKey);

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
    try
    {
      var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
      if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
      {
        return null;
      }
      return principal;
    }
    catch (Exception)
    {
      return null;
    }
  }
}

