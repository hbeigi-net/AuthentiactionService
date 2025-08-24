using System;
using System.Security.Claims;
using Domain.Entities;

namespace Application.Intefaces;

public interface IJwtTokenService
{
    Task<string> GenerateAccessTokenAsync(ApplicationUser user);
    string GenerateRefreshToken(ApplicationUser user);
    ClaimsPrincipal? ValidateToken(string token, string secretKey);
} 
