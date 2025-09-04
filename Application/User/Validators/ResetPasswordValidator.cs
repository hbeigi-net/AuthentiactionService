using Application.User.Commands;
using FluentValidation;

namespace Application.User.Validators;

public class ResetPasswordValidator : AbstractValidator<ResetPassword.Command>
{
  public ResetPasswordValidator()
  {
    RuleFor(x => x.Email)
      .NotEmpty().WithMessage("Email is required");

    RuleFor(x => x.Token)
      .NotEmpty().WithMessage("Token is required");
    
    RuleFor(x => x.NewPassword)
      .NotEmpty().WithMessage("New password is required");

    RuleFor(x => x.NewPassword)
      .MinimumLength(8).WithMessage("New password must be at least 8 characters long")
      .Matches("[A-Z]").WithMessage("New password must contain at least one uppercase letter")
      .Matches("[a-z]").WithMessage("New password must contain at least one lowercase letter")
      .Matches("[0-9]").WithMessage("New password must contain at least one number")
      .Matches("[^a-zA-Z0-9]").WithMessage("New password must contain at least one special character");
  }
}