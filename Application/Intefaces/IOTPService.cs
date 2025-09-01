
namespace Application.Intefaces;

public interface IOTPService
{
  Task<bool> SendSigninOtpAsync(string phoneNumber);
  Task<bool> SendSignupOtpAsync(string phoneNumber);

  Task<bool> VerifySigninOtpAsync(string phoneNumber, string otp);
  Task<bool> VerifySingupOtpAsync(string phoneNumber, string otp);
}