using Application.Auth.Commands;
using Application.Auth.DTOs;
using Application.Intefaces;
using Domain.Entities;
using Microsoft.Extensions.Logging;
using AutoMapper;
using Application.Interfaces;
using Persistence.Data;
using Application.Core;
using MediatR;
using Microsoft.Extensions.Configuration;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Application.Core.Models;
using System.Text;
using System.Buffers.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace Infrastructure.Services;

public class AuthService(
        IUnitOfWork unitOfWork,
        IJwtTokenService jwtTokenService,
        ILogger<AuthService> logger,
        IMapper mapper,
        AuthDbContext dbContext,
        IConfiguration config,
        ICurrentUserService currentUserService,
        IOptions<JwtSettings> jwtSettings,
        IEmailService emailService
 ) : IAuthService
{
    private readonly JwtSettings _jwtSettings = jwtSettings.Value;
    private readonly IUnitOfWork _unitOfWork = unitOfWork;
    private readonly IJwtTokenService _jwtTokenService = jwtTokenService;
    private readonly IMapper _mapper = mapper;
    private readonly ILogger<AuthService> _logger = logger;
    private readonly AuthDbContext _dbContext = dbContext;
    private readonly IConfiguration _config = config;
    private readonly ICurrentUserService _currentUserService = currentUserService;
    private readonly IEmailService _emailService = emailService;

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
            
            if(!user.EmailConfirmed) {
                _logger.LogWarning("Login attempt with unconfirmed email: {Email}", request.Email);
                return ApplicationResult<SigninResponseDTO>.Fail("Email not confirmed, Please Verify your email");
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
            var isEmailTaken = await _unitOfWork.Users.IsEmailTakenAsync(request.Email);
            if (isEmailTaken)
                return ApplicationResult<SingupResponseDTO>.Fail("Email is already taken");

            await _unitOfWork.BeginTransactionAsync();

            var userManager = _unitOfWork.SignInManager.UserManager;
            var signInManager = _unitOfWork.SignInManager;
            

            Guid userId = Guid.NewGuid();
            var user = new ApplicationUser
            {
                Id = userId,
                UserName = request.Email,
                Email = request.Email,
                EmailConfirmed = false,
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

            var emailVerificationToken = await userManager.GenerateEmailConfirmationTokenAsync(user);
            
            bool isEmailSent = await SendVerificationEmailAsync(user.Email!, emailVerificationToken);

            if (!isEmailSent)
            {
                await _unitOfWork.RollbackTransactionAsync();
                return ApplicationResult<SingupResponseDTO>.Fail("Failed to send verification email", 500);
            }

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

    public async Task<ApplicationResult<bool>> LogoutAsync(string refreshToken, CancellationToken cancellationToken)
    {
        var tokeClaims = _jwtTokenService.ValidateToken(refreshToken, _jwtSettings.RefreshTokenSecretKey);
        if (tokeClaims is null)
        {
            return ApplicationResult<bool>.Fail("Invalid refresh token");
        }

        var token = await _dbContext.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == refreshToken, cancellationToken);
        if (token is null)
        {
            return ApplicationResult<bool>.Fail("Invalid refresh token");
        }

        token.Revoke("UserLogout");
        await _dbContext.SaveChangesAsync(cancellationToken);

        return ApplicationResult<bool>.Ok(true);
    }

    public async Task<ApplicationResult<bool>> RevokeAllTokensAsync(string userId, CancellationToken cancellationToken)
    {
        var id = Guid.Parse(userId);
        var refereshTokens = await _dbContext.RefreshTokens
            .Where(rt => rt.UserId == id )
            .ToListAsync(cancellationToken);

        if(refereshTokens is null) return ApplicationResult<bool>.Fail("No refresh tokens found");

        foreach (var token in refereshTokens)
        {
            token.Revoke("UserLogout");
        }

        await _dbContext.SaveChangesAsync(cancellationToken);

        return ApplicationResult<bool>.Ok(true);
    }

    public async Task<ApplicationResult<bool>> ConfirmEmailAsync(string email, string token)
    {
        try
        {
            var userManager = _unitOfWork.SignInManager.UserManager;
            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return ApplicationResult<bool>.Fail("User not found");
            }
            var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
            var result = await userManager.ConfirmEmailAsync(user, decodedToken);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return ApplicationResult<bool>.Fail(errors);
            }

            _logger.LogInformation("Email confirmed for user: {UserId}", user.Id);
            return ApplicationResult<bool>.Redirect($"{_config["ClientOptions:ClientLoginUrl"]}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error confirming email for user: {Email}", email);
            return ApplicationResult<bool>.Fail("An error occurred while confirming email");
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

        var claims = _jwtTokenService.ValidateToken(token, _jwtSettings.RefreshTokenSecretKey);

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

    public async Task<ApplicationResult<bool>> ChangePasswordAsync(ChangePassword.Command request, CancellationToken cancellationToken)
    {
        var userId = _currentUserService.GetUserId();

        if (userId is null)
        {
            return ApplicationResult<bool>.Fail("User not found", 400);
        }

        var singinManager = _unitOfWork.SignInManager;
        var user = await _unitOfWork.Users.GetByIdAsync(userId.Value);

        if (user is null)
        {
            return ApplicationResult<bool>.Fail("User not found", 400);
        }

        var result = await singinManager.CheckPasswordSignInAsync(user, request.CurrentPassword, lockoutOnFailure: true);

        if (result.IsLockedOut)
        {
            return ApplicationResult<bool>.Fail("Too many requests, please try again later", 429);
        }

        if (!result.Succeeded)
        {
            return ApplicationResult<bool>.Fail("Invalid current password", 400);
        }

        user.PasswordHash = singinManager.UserManager.PasswordHasher.HashPassword(user, request.NewPassword);
        user.PasswordUpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var updateResult = await singinManager.UserManager.UpdateAsync(user);

        if (!updateResult.Succeeded)
        {
            return ApplicationResult<bool>.Fail("something went wrong saving changes", 500);
        }

        await RevokeAllTokensAsync(user.Id.ToString(), cancellationToken);
        return ApplicationResult<bool>.Ok(true);
    }

    public async Task<ApplicationResult<bool>> ResendVerificationEmailAsync(string email)
    {
        var userManager = _unitOfWork.SignInManager.UserManager;
        var user = await userManager.FindByEmailAsync(email);
        if (user is null)
        {
            return ApplicationResult<bool>.Fail("User not found");
        }
        var verificationToken = await userManager.GenerateEmailConfirmationTokenAsync(user);
        verificationToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(verificationToken));
        if(user.EmailConfirmed)
        {
            return ApplicationResult<bool>.Fail("Email already confirmed");
        }

        if(!user.IsActive)
        {
            return ApplicationResult<bool>.Fail("User is not active");
        }

        var emailVerificationToken = await userManager.GenerateEmailConfirmationTokenAsync(user);
        bool isEmailSent = await SendVerificationEmailAsync(user.Email!, emailVerificationToken);

        if (!isEmailSent)
        {
            return ApplicationResult<bool>.Fail("Failed to send verification email", 500);
        }

        return ApplicationResult<bool>.Ok(true);

    }

    private async Task<bool> SendVerificationEmailAsync(string email, string token)
    {
        var verificationToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var verificationLink = $"{_config["ClientOptions:ClientUrl"]}{_config["VerificationPath"]}?email={email}&token={verificationToken}";
        
        return await _emailService.SendEmailAsync(new EmailMessage{
                To = email,
                Subject = "Welcome to our app",
                Body = $$"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Email Verification</title>
                    <style>
                        * {
                            margin: 0;
                            padding: 0;
                            box-sizing: border-box;
                        }
                        
                        body {
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            line-height: 1.6;
                            color: #333;
                            background-color: #f4f4f4;
                        }
                        
                        .email-container {
                            max-width: 600px;
                            margin: 0 auto;
                            background-color: #ffffff;
                            border-radius: 8px;
                            overflow: hidden;
                            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                        }
                        
                        .header {
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            padding: 30px 20px;
                            text-align: center;
                        }
                        
                        .header h1 {
                            font-size: 28px;
                            font-weight: 600;
                            margin-bottom: 10px;
                        }
                        
                        .header p {
                            font-size: 16px;
                            opacity: 0.9;
                        }
                        
                        .content {
                            padding: 40px 30px;
                        }
                        
                        .welcome-text {
                            font-size: 18px;
                            color: #2c3e50;
                            margin-bottom: 25px;
                            text-align: center;
                        }
                        
                        .verification-button {
                            display: inline-block;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            text-decoration: none;
                            padding: 15px 30px;
                            border-radius: 25px;
                            font-weight: 600;
                            font-size: 16px;
                            margin: 20px 0;
                            text-align: center;
                            transition: all 0.3s ease;
                            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
                        }
                        
                        .verification-button:hover {
                            transform: translateY(-2px);
                            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
                        }
                        
                        .info-text {
                            background-color: #f8f9fa;
                            border-left: 4px solid #667eea;
                            padding: 15px;
                            margin: 20px 0;
                            border-radius: 0 4px 4px 0;
                        }
                        
                        .footer {
                            background-color: #f8f9fa;
                            padding: 20px 30px;
                            text-align: center;
                            border-top: 1px solid #e9ecef;
                        }
                        
                        .footer p {
                            color: #6c757d;
                            font-size: 14px;
                            margin-bottom: 10px;
                        }
                        
                        .security-note {
                            background-color: #fff3cd;
                            border: 1px solid #ffeaa7;
                            border-radius: 4px;
                            padding: 15px;
                            margin: 20px 0;
                            color: #856404;
                        }
                        
                        @media only screen and (max-width: 600px) {
                            .email-container {
                                margin: 10px;
                                border-radius: 4px;
                            }
                            
                            .header {
                                padding: 20px 15px;
                            }
                            
                            .header h1 {
                                font-size: 24px;
                            }
                            
                            .content {
                                padding: 25px 20px;
                            }
                            
                            .verification-button {
                                padding: 12px 25px;
                                font-size: 14px;
                            }
                        }
                    </style>
                </head>
                <body>
                    <div class="email-container">
                        <div class="header">
                            <h1>🎉 Welcome!</h1>
                            <p>Thank you for joining our community</p>
                        </div>
                        
                        <div class="content">
                            <div class="welcome-text">
                                <p>Hi there! 👋</p>
                                <p>We're excited to have you on board. To get started, please verify your email address by clicking the button below.</p>
                            </div>
                            
                            <div style="text-align: center;">
                                <a href="{{verificationLink}}" class="verification-button">
                                    ✅ Verify Email Address
                                </a>
                            </div>
                            
                            <div class="info-text">
                                <strong>What happens next?</strong><br>
                                After verifying your email, you'll have full access to all our features and services.
                            </div>
                            
                            <div class="security-note">
                                <strong>🔒 Security Note:</strong> If you didn't create an account with us, please ignore this email. Your account security is important to us.
                            </div>
                        </div>
                        
                        <div class="footer">
                            <p>This email was sent to you because you signed up for our service.</p>
                            <p>If you have any questions, please don't hesitate to contact our support team.</p>
                            <p style="margin-top: 15px; font-size: 12px; color: #adb5bd;">
                                © 2024 Your App Name. All rights reserved.
                            </p>
                        </div>
                    </div>
                </body>
                </html>
                """
            });
    }
}
