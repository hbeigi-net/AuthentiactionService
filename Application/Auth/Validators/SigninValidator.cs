using System;
using Application.Auth.Commands;
using FluentValidation;

namespace Application.Auth.Validators;

public class SigninValidator: AbstractValidator<SignIn.Command>
{
    public SigninValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required")
            .EmailAddress().WithMessage("Invalid email format");

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required");
    }
}
