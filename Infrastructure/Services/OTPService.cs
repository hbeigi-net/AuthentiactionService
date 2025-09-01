
using Application.Intefaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Infrastructure.Services;

public class OTPService(
  ICacheService cacheService,
  ISMSService smsService,
  ILogger<OTPService> logger,
  IConfiguration configuration
) : IOTPService
{
  private readonly IConfiguration _configuration = configuration;
  private readonly ILogger _logger = logger;
  private readonly ICacheService _cacheService = cacheService;
  private readonly ISMSService _smsService = smsService;

  public async Task<bool> SendSigninOtpAsync(string phoneNumber)
  {
    try
    {
      int.TryParse(_configuration["OTP:SigninLifeSpanInMinute"], out int lifeSpanMinute);
      var lifeSpan = TimeSpan.FromMinutes(lifeSpanMinute);

      var cacheKey = GetSinginCacheKey(phoneNumber);
      var otp = GenerateOtp();

      await _cacheService.SetAsync(cacheKey, otp, lifeSpan);

      _logger.LogInformation("signin otp sent");
      return true;
    }
    catch (Exception exp)
    {
      _logger.LogError(exp, "error sending login otp");
      return false;
    }
  }

  public async Task<bool> SendSignupOtpAsync(string phoneNumber)
  {
    try
    {
      int.TryParse(_configuration["OTP:SignupLifeSpanInMinute"], out int parseResult);
      var lifeSpan = TimeSpan.FromMinutes(parseResult); // 2 Minutes

      var otp = GenerateOtp();
      var cacheKey = GetSignupCacheKey(phoneNumber);

      //var isOTPSent = await _smsService.SendOTPAsync(phoneNumber, "123456", cancellationToken);
      //if(!isOTPSent)
      //{
      //   return false;
      //}

      await _cacheService.SetAsync(cacheKey, otp, lifeSpan);
      _logger.LogInformation("singup OTP sent to {PhoneNumber}", phoneNumber);

      return true;
    }
    catch (Exception exp)
    {
      _logger.LogError(exp, "Exception Occured while sending otp");
      return false;
    }
  }

  public async Task<bool> VerifySigninOtpAsync(string phoneNumber, string otp)
  {
    var cacheKey = GetSinginCacheKey(phoneNumber);
    var storedOTP = await _cacheService.GetAsync<string>(cacheKey);

    if (storedOTP == otp)
    {
      await _cacheService.RemoveAsync(cacheKey);
      return true;
    }

    return false;
  }

  public async Task<bool> VerifySingupOtpAsync(string phoneNumber, string otp)
  {
    var cacheKey = GetSignupCacheKey(phoneNumber);
    var storedOTP = await _cacheService.GetAsync<string>(cacheKey);

    if (storedOTP == otp)
    {
      await _cacheService.RemoveAsync(cacheKey);
      return true;
    }

    return false;
  }

  private static string GetSignupCacheKey(string phoneNumber) => $"singup-otp:{phoneNumber}";

  private static string GetSinginCacheKey(string phoneNumber) => $"signin-otp:{phoneNumber}";

  private static string GenerateOtp() => "123456";
}
