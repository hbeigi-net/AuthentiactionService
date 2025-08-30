

using Application.Auth.Commands;
using FluentValidation;

namespace Application.Auth.Validators;
public class MobileSignupValidator: AbstractValidator<PhoneSignup.Command>
{
  public MobileSignupValidator(){
    
        RuleFor(x => x.PhoneNumber)
            .NotEmpty().WithMessage("Phone number is required")
            .Matches("^\\+?[1-9]\\d{1,14}$").WithMessage("Invalid phone number format");
  }
}