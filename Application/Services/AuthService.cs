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

namespace Application.Services;

public class AuthService(
        IUnitOfWork unitOfWork,
        IJwtTokenService jwtTokenService,
        ILogger<AuthService> logger,
        IMapper mapper
        //IEmailService emailService) : IAuthService
 ) : IAuthService
{
    private readonly IUnitOfWork _unitOfWork = unitOfWork;
    private readonly IJwtTokenService _jwtTokenService = jwtTokenService;
    private readonly IMapper _mapper = mapper;
    private readonly ILogger<AuthService> _logger = logger;
    //private readonly IEmailService _emailService;

    public async Task<Result<SigninResponseDTO>> SignInAsync(SignIn.Command request)
    {
        try
        {
            var userManager = _unitOfWork.SignInManager.UserManager;
            var signInManager = _unitOfWork.SignInManager;
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                _logger.LogWarning("Login attempt with non-existent email: {Email}", request.Email);
                return Result.Fail<SigninResponseDTO>("Invalid email or password");
            }

            if (!user.IsActive)
            {
                _logger.LogWarning("Login attempt with inactive account: {Email}", request.Email);
                return Result.Fail<SigninResponseDTO>("invalid credentials");
            }

            var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

            if (result.IsLockedOut)
                return Result.Fail<SigninResponseDTO>("Too many requests, please try again later");

            if (result.RequiresTwoFactor)
                return Result.Fail<SigninResponseDTO>("Two-factor authentication required, please check your email for the code");

            if (!result.Succeeded)
            {
                _logger.LogWarning("Failed login attempt for email: {Email}", request.Email);
                return Result.Fail<SigninResponseDTO>("Invalid credentials");
            }

            // Update last login
            user.UpdateLastLogin();
            await signInManager.UserManager.UpdateAsync(user);   

            // Generate tokens
            var accessToken = await _jwtTokenService.GenerateAccessTokenAsync(user);
            var refreshToken = _jwtTokenService.GenerateRefreshToken();

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
            return Result.Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login for email: {Email}", request.Email);
            return Result.Fail<SigninResponseDTO>("An error occurred during login");
        }
    }

    public async Task<Result<SingupResponseDTO>> SignUpAsync(Singup.Command request)
    {
        try
        {
            // Check if email already exists
            var isEmailTaken = await _unitOfWork.Users.IsEmailTakenAsync(request.Email);
            if (isEmailTaken)
                return Result.Fail<SingupResponseDTO>("Email is already taken");

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
                return Result.Fail<SingupResponseDTO>(errors);
            }

            // Assign default role
            //await userManager.AddToRoleAsync(user, "User");

            // Generate email confirmation token
            var emailToken = await userManager.GenerateEmailConfirmationTokenAsync(user);

            // Send confirmation email
            //await _emailService.SendEmailConfirmationAsync(user.Email, user.FullName, user.Id.ToString(), emailToken);

            await _unitOfWork.CommitTransactionAsync();

            _logger.LogInformation("User {UserId} registered successfully", user.Id);
            return Result.Ok(new SingupResponseDTO());
        }
        catch (Exception ex)
        {
            await _unitOfWork.RollbackTransactionAsync();
            _logger.LogError(ex, "Error during registration for email: {Email}", request.Email);
            return Result.Fail<SingupResponseDTO>("An error occurred during registration");
        }
    }

    public async Task<Result> LogoutAsync(string refreshToken)
    {
        try
        {
            await _unitOfWork.RefreshTokens.RevokeAsync(refreshToken, "UserLogout");
            await _unitOfWork.SaveChangesAsync();
            return Result.Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout");
            return Result.Fail("An error occurred during logout");
        }
    }

    public async Task<Result> RevokeAllTokensAsync(Guid userId)
    {
        try
        {
            await _unitOfWork.RefreshTokens.RevokeAllUserTokensAsync(userId, "SystemRevoke");
            await _unitOfWork.SaveChangesAsync();
            return Result.Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error revoking tokens for user: {UserId}", userId);
            return Result.Fail("An error occurred while revoking tokens");
        }
    }

    public async Task<Result> ConfirmEmailAsync(string userId, string token)
    {
        try
        {
            var userManager = _unitOfWork.SignInManager.UserManager;
            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
                return Result.Fail("User not found");

            var result = await userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return Result.Fail(errors);
            }

            _logger.LogInformation("Email confirmed for user: {UserId}", userId);
            return Result.Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error confirming email for user: {UserId}", userId);
            return Result.Fail("An error occurred while confirming email");
        }
    }

    public async Task<Result> ForgotPasswordAsync(string email)
    {
        try
        {
            var userManager = _unitOfWork.SignInManager.UserManager;
            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                // Don't reveal if email exists or not for security
                _logger.LogInformation("Password reset requested for email: {Email}", email);
                return Result.Ok();
            }

            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            
            // Send password reset email
            //await _emailService.SendPasswordResetAsync(user.Email, user.FullName, user.Id.ToString(), token);

            _logger.LogInformation("Password reset email sent for user: {UserId}", user.Id);
            return Result.Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing forgot password for email: {Email}", email);
            return Result.Fail("An error occurred while processing password reset");
        }
    }
}
