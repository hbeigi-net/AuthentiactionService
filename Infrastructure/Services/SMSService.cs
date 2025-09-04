

using Application.Interfaces;

namespace Infrastructure.Services;

public class SMSService() : ISMSService
{
  public Task<bool> SendOTPAsync(string phoneNumber, string otp, CancellationToken cancellationToken = default)
  {
    throw new NotImplementedException();
  }
}
