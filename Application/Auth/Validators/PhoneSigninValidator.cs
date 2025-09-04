
using Application.Auth.Commands;
using FluentValidation;

namespace Application.Auth.Validators;

public class PhoneSigninValidator : AbstractValidator<PhoneSignin.Command>
{
  public PhoneSigninValidator()
  {
    RuleFor(x => x.PhoneNumber)
      .NotEmpty().WithMessage("Phone number is required.")
      .Matches("^\\+?[1-9]\\d{1,14}$").WithMessage("Invalid phone number format");

    RuleFor(x => x.OTP)
      .NotEmpty().WithMessage("OTP is required");
  }
}