

using Application.Auth.Commands;
using FluentValidation;

namespace Application.Auth.Validators;

public class RequestSigninOtpValidator : AbstractValidator<RequestSinginOtp.Command>
{
  public RequestSigninOtpValidator()
  {
    RuleFor(x => x.PhoneNumber)
      .NotEmpty().WithMessage("Phone number is required")
      .Matches("^\\+?[1-9]\\d{1,14}$").WithMessage("Invalid phone number format");

  }
}