using System;
using Application.Auth.Commands;
using Application.Auth.DTOs;
using Application.Intefaces;
using Domain.Entities;
using Domain.Interfaces;
using FluentResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using AutoMapper;
using Infrastructure.Interfaces;
using Persistence.Data;
using Microsoft.EntityFrameworkCore;
using Application.Core;
using MediatR;
using Microsoft.Extensions.Configuration;
using System.Security.Claims;

namespace Infrastructure.Services;

public class AuthService(
        IUnitOfWork unitOfWork,
        IJwtTokenService jwtTokenService,
        ILogger<AuthService> logger,
        IMapper mapper,
        AuthDbContext dbContext,
        IConfiguration config
 //IEmailService emailService) : IAuthService
 ) : IAuthService
{
    private readonly IUnitOfWork _unitOfWork = unitOfWork;
    private readonly IJwtTokenService _jwtTokenService = jwtTokenService;
    private readonly IMapper _mapper = mapper;
    private readonly ILogger<AuthService> _logger = logger;
    private readonly AuthDbContext _dbContext = dbContext;
    private readonly IConfiguration _config = config;
    //private readonly IEmailService _emailService;

    public async Task<ApplicationResult<SigninResponseDTO>> SignInAsync(SignIn.Command request)
    {
        try
        {
            var userManager = _unitOfWork.SignInManager.UserManager;
            var signInManager = _unitOfWork.SignInManager;
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                _logger.LogWarning("Login attempt with non-existent email: {Email}", request.Email);
                return ApplicationResult<SigninResponseDTO>.Fail("Invalid Creadentials");
            }

            if (!user.IsActive)
            {
                _logger.LogWarning("Login attempt with inactive account: {Email}", request.Email);
                return ApplicationResult<SigninResponseDTO>.Fail("invalid credentials");
            }

            var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

            if (result.IsLockedOut)
                return ApplicationResult<SigninResponseDTO>.Fail("Too many requests, please try again later");

            if (result.RequiresTwoFactor)
                return ApplicationResult<SigninResponseDTO>.Fail("Two-factor authentication required, please check your email for the code");

            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed login attempt for email: {Email}", request.Email);
                return ApplicationResult<SigninResponseDTO>.Fail("Invalid credentials");
            }

            // Update last login
            user.UpdateLastLogin();
            await signInManager.UserManager.UpdateAsync(user);

            // Generate tokens
            var accessToken = await _jwtTokenService.GenerateAccessTokenAsync(user);
            var refreshToken = _jwtTokenService.GenerateRefreshToken(user);

            // Save refresh token
            var refreshTokenEntity = new RefreshToken
            {
                Token = refreshToken,
                ExpiryDate = DateTime.UtcNow.AddDays(request.RememberMe ? 30 : 7),
                UserId = user.Id,
                DeviceInfo = request.DeviceInfo,
                IpAddress = request.IpAddress,
                CreatedAt = DateTime.UtcNow,
                CreatedBy = user.Id.ToString(),
            };

            await _unitOfWork.RefreshTokens.CreateAsync(refreshTokenEntity);
            await _unitOfWork.SaveChangesAsync();

            var response = new SigninResponseDTO
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
            };

            _logger.LogInformation("User {UserId} logged in successfully", user.Id);
            return ApplicationResult<SigninResponseDTO>.Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login for email: {Email}", request.Email);
            return ApplicationResult<SigninResponseDTO>.Fail("An error occurred during login");
        }
    }

    public async Task<ApplicationResult<SingupResponseDTO>> SignUpAsync(Singup.Command request)
    {
        try
        {
            // Check if email already exists
            var isEmailTaken = await _unitOfWork.Users.IsEmailTakenAsync(request.Email);
            if (isEmailTaken)
                return ApplicationResult<SingupResponseDTO>.Fail("Email is already taken");

            await _unitOfWork.BeginTransactionAsync();

            var userManager = _unitOfWork.SignInManager.UserManager;
            var signInManager = _unitOfWork.SignInManager;
            // Create new user
            Guid userId = Guid.NewGuid();
            var user = new ApplicationUser
            {
                Id = userId,
                UserName = request.Email,
                Email = request.Email,
                EmailConfirmed = false, // Require email confirmation
                CreatedAt = DateTime.UtcNow,
                CreatedBy = userId.ToString(),
            };

            var result = await userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                await _unitOfWork.RollbackTransactionAsync();
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return ApplicationResult<SingupResponseDTO>.Fail(errors);
            }

            // Assign default role
            //await userManager.AddToRoleAsync(user, "User");

            // Generate email confirmation token
            var emailToken = await userManager.GenerateEmailConfirmationTokenAsync(user);

            // Send confirmation email
            //await _emailService.SendEmailConfirmationAsync(user.Email, user.FullName, user.Id.ToString(), emailToken);

            await _unitOfWork.CommitTransactionAsync();

            _logger.LogInformation("User {UserId} registered successfully", user.Id);
            return ApplicationResult<SingupResponseDTO>.Ok(new SingupResponseDTO());
        }
        catch (Exception ex)
        {
            await _unitOfWork.RollbackTransactionAsync();
            _logger.LogError(ex, "Error during registration for email: {Email}", request.Email);
            return ApplicationResult<SingupResponseDTO>.Fail("An error occurred during registration");
        }
    }

    public async Task<ApplicationResult<Unit>> LogoutAsync(string refreshToken)
    {
        try
        {
            await _unitOfWork.RefreshTokens.RevokeAsync(refreshToken, "UserLogout");
            await _unitOfWork.SaveChangesAsync();
            return ApplicationResult<Unit>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout");
            return ApplicationResult<Unit>.Fail("An error occurred during logout");
        }
    }

    public async Task<ApplicationResult<Unit>> RevokeAllTokensAsync(Guid userId)
    {
        try
        {
            await _unitOfWork.RefreshTokens.RevokeAllUserTokensAsync(userId, "SystemRevoke");
            await _unitOfWork.SaveChangesAsync();
            return ApplicationResult<Unit>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking tokens for user: {UserId}", userId);
            return ApplicationResult<Unit>.Fail("An error occurred while revoking tokens");
        }
    }

    public async Task<ApplicationResult<Unit>> ConfirmEmailAsync(string userId, string token)
    {
        try
        {
            var userManager = _unitOfWork.SignInManager.UserManager;
            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
                return ApplicationResult<Unit>.Fail("User not found");

            var result = await userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return ApplicationResult<Unit>.Fail(errors);
            }

            _logger.LogInformation("Email confirmed for user: {UserId}", userId);
            return ApplicationResult<Unit>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error confirming email for user: {UserId}", userId);
            return ApplicationResult<Unit>.Fail("An error occurred while confirming email");
        }
    }

    public async Task<ApplicationResult<Unit>> ForgotPasswordAsync(string email)
    {
        try
        {
            var userManager = _unitOfWork.SignInManager.UserManager;
            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                // Don't reveal if email exists or not for security
                _logger.LogInformation("Password reset requested for email: {Email}", email);
                return ApplicationResult<Unit>.Ok(Unit.Value);
            }

            var token = await userManager.GeneratePasswordResetTokenAsync(user);

            // Send password reset email
            //await _emailService.SendPasswordResetAsync(user.Email, user.FullName, user.Id.ToString(), token);

            _logger.LogInformation("Password reset email sent for user: {UserId}", user.Id);
            return ApplicationResult<Unit>.Ok(Unit.Value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing forgot password for email: {Email}", email);
            return ApplicationResult<Unit>.Fail("An error occurred while processing password reset");
        }
    }

    public async Task<ApplicationResult<RefreshTokenResponseDto>> RefreshToken(string token)
    {

        var refreshToken = await _unitOfWork.RefreshTokens.GetByTokenAsync(token);

        if (refreshToken is null)
        {
            return ApplicationResult<RefreshTokenResponseDto>.Fail("Invalid refresh refreshToken");
        }

        if (refreshToken.IsRevoked || refreshToken.IsExpired)
        {
            return ApplicationResult<RefreshTokenResponseDto>.Fail("refreshToken is revoked or expired");
        }

        var claims = _jwtTokenService.ValidateToken(token, _config["JwtSettings:RefreshTokenSecretKey"]!);

        if (claims is null)
        {
            return ApplicationResult<RefreshTokenResponseDto>.Fail("Invalid Token");
        }

        var userId = claims.Claims.FirstOrDefault(cl => cl.Type == ClaimTypes.NameIdentifier)?.Value;

        if (userId is null)
        {
            return ApplicationResult<RefreshTokenResponseDto>.Fail("User not found");
        }

        var user = await _unitOfWork.Users.GetByIdAsync(Guid.Parse(userId));
        if (user is null)
        {
            return ApplicationResult<RefreshTokenResponseDto>.Fail("Invalid refreshToken. Please login again");
        }

        var accessToken = await _jwtTokenService.GenerateAccessTokenAsync(user);
        return ApplicationResult<RefreshTokenResponseDto>.Ok(new()
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken.Token,
        });
    }
}
