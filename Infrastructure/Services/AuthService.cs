using Application.Auth.Commands;
using Application.Auth.DTOs;
using Application.Interfaces;
using Domain.Entities;
using Microsoft.Extensions.Logging;
using AutoMapper;
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
using Application.User.Commands;

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
        IEmailService emailService,
        ISMSService smsService,
        IOTPService otpService, 
        IEmailTemplateService emailTemplateService
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
    private readonly ISMSService _smsService = smsService;
    private readonly IOTPService _otpService = otpService;
    private readonly IEmailTemplateService _emailTemplateService = emailTemplateService;
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

            if (!user.EmailConfirmed)
            {
                _logger.LogWarning("Login attempt with unconfirmed email: {Email}", request.Email);
                return ApplicationResult<SigninResponseDTO>.Fail("Email not confirmed, Please Verify your email");
            }

            if (!user.IsActive)
            {
                _logger.LogWarning("Login attempt with inactive account: {Email}", request.Email);
                return ApplicationResult<SigninResponseDTO>.Fail("invalid credentials");
            }

            if (!user.HasPassword)
            {
                _logger.LogWarning("Login attempt with passwordless account: {Email}", request.Email);
                return ApplicationResult<SigninResponseDTO>.Fail("This account is not password protected, Use Phone Number and OTP to login");
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
                HasPassword = true
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
    public async Task<ApplicationResult<SingupResponseDTO>> PhoneSignUpAsync(PhoneSignup.Command request, CancellationToken cancellationToken)
    {
        var phoneNumber = request.PhoneNumber;
        var isOtpSent = await _otpService.SendSignupOtpAsync(phoneNumber);

        if (!isOtpSent)
        {
            return ApplicationResult<SingupResponseDTO>.Fail("An Error Occured while sending OTP");
        }

        return ApplicationResult<SingupResponseDTO>.Ok(new SingupResponseDTO());
    }
    public async Task<ApplicationResult<SigninResponseDTO>> CompletePhoneSingup(CompletePhoneSignup.Command request, CancellationToken cancellationToken)
    {
        var otpVerified = await _otpService.VerifySingupOtpAsync(request.PhoneNumber, request.OTP);
        var isPhoneNumberTaken = await _unitOfWork.Users.IsPhoneNumberTakenAsync(request.PhoneNumber);

        if (isPhoneNumberTaken)
        {
            return ApplicationResult<SigninResponseDTO>.Fail("PhoneNumber alrady Exists");
        }

        if (!otpVerified)
        {
            return ApplicationResult<SigninResponseDTO>.Fail("Invalid OTP");
        }

        try
        {
            await _unitOfWork.BeginTransactionAsync();
            var newUser = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = request.PhoneNumber,
                PhoneNumber = request.PhoneNumber,
                PhoneNumberConfirmed = true,
                IsActive = true,
                HasPassword = false,
                CreatedAt = DateTime.UtcNow,
            };

            var userCreated = await _unitOfWork.Users.CreateAsync(newUser);
            if (!userCreated)
            {
                return ApplicationResult<SigninResponseDTO>.Fail("Error creatingUser");
            }
            var aToken = await _jwtTokenService.GenerateAccessTokenAsync(newUser);
            await _unitOfWork.CommitTransactionAsync();

            return ApplicationResult<SigninResponseDTO>.Ok(new SigninResponseDTO
            {
                AccessToken = aToken,
                // no refresh token for login with otp
                RefreshToken = "",
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating new user for phone number: {PhoneNumber}", request.PhoneNumber);
            return ApplicationResult<SigninResponseDTO>.Fail("An error occurred while creating new user");
        }

    }
    public async Task<ApplicationResult<bool>> RequestSigninOtp(RequestSinginOtp.Command request)
    {
        // may i should check for phone number to exist before sending signin otp
        var otpSent = await _otpService.SendSigninOtpAsync(request.PhoneNumber);

        if (!otpSent)
        {
            return ApplicationResult<bool>.Fail("an Error occured while trying send otp");
        }

        return ApplicationResult<bool>.Ok(true);
    }
    public async Task<ApplicationResult<SigninResponseDTO>> PhoneSignInAsync(PhoneSignin.Command request)
    {
        var otpVerified = await _otpService.VerifySigninOtpAsync(request.PhoneNumber, request.OTP);

        if (!otpVerified)
        {
            return ApplicationResult<SigninResponseDTO>.Fail("Invalid OTP");
        }

        var user = await _unitOfWork.Users.GetByPhoneNumberAsync(request.PhoneNumber);
        if (user is null)
        {
            return ApplicationResult<SigninResponseDTO>.Fail("User not Found");
        }

        var accessToken = await _jwtTokenService.GenerateAccessTokenAsync(user);

        return ApplicationResult<SigninResponseDTO>.Ok(new SigninResponseDTO
        {
            AccessToken = accessToken,
            RefreshToken = "",
        });
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
            .Where(rt => rt.UserId == id)
            .ToListAsync(cancellationToken);

        if (refereshTokens is null) return ApplicationResult<bool>.Fail("No refresh tokens found");

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

    public async Task<ApplicationResult<bool>> ForgotPasswordAsync(string email)
    {
        try
        {
            var userManager = _unitOfWork.SignInManager.UserManager;
            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                // Don't reveal if email exists or not for security
                _logger.LogInformation("Password reset requested for email: {Email}", email);
                return ApplicationResult<bool>.Ok(true);
            }

            var token = await userManager.GeneratePasswordResetTokenAsync(user);

            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            // Send password reset email
            var emailTemplate = _emailTemplateService.GetResetPasswordTemplate(user.Email!, encodedToken);
            var emailSent = await _emailService.SendEmailAsync(emailTemplate);

            if (!emailSent)
            {
                return ApplicationResult<bool>.Fail("Failed to send password reset email", 500);
            }

            _logger.LogInformation("Password reset email sent for user: {UserId}", user.Id);
            return ApplicationResult<bool>.Ok(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing forgot password for email: {Email}", email);
            return ApplicationResult<bool>.Fail("An error occurred while processing password reset");
        }
    }

    public async Task<ApplicationResult<bool>> ResetPasswordAsync(ResetPassword.Command request)
    {
        var userManager = _unitOfWork.SignInManager.UserManager;
        var user = await userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            return ApplicationResult<bool>.Fail("User not found");
        }

        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token));
        var result = await userManager.ResetPasswordAsync(user, decodedToken, request.NewPassword);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            return ApplicationResult<bool>.Fail(errors);
        }

        return ApplicationResult<bool>.Redirect($"{_config["ClientOptions:ClientLoginUrl"]}");
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

        if (!user.HasPassword)
        {
            return ApplicationResult<bool>.Fail("Password change not permited");
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
        if (user.EmailConfirmed)
        {
            return ApplicationResult<bool>.Fail("Email already confirmed");
        }

        if (!user.IsActive)
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
        var emailTemplate = _emailTemplateService.GetEmailVerificationTemplate(email, token);

        return await _emailService.SendEmailAsync(emailTemplate);
    }
}
