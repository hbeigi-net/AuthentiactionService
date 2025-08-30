
namespace Application.Intefaces;

public interface ISMSService
{
  Task<bool> SendOTPAsync(string phoneNumber, string otp, CancellationToken cancellationToken = default);
}