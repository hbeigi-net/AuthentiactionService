

using Application.Auth.Commands;
using FluentValidation;

namespace Application.Auth.Validators;

public class ChangePasswordValidator : AbstractValidator<ChangePassword.Command>
{
  public ChangePasswordValidator()
  {
    RuleFor(x => x.NewPassword)
        .NotEmpty().WithMessage("Password is required")
        .MinimumLength(8).WithMessage("Password must be at least 8 characters long")
        .Matches("[A-Z]").WithMessage("Password must contain at least one uppercase letter")
        .Matches("[a-z]").WithMessage("Password must contain at least one lowercase letter")
        .Matches("[0-9]").WithMessage("Password must contain at least one number")
        .Matches("[^a-zA-Z0-9]").WithMessage("Password must contain at least one special character");

    RuleFor(x => x.CurrentPassword)
        .NotEmpty().WithMessage("Current password is required");
  }
}