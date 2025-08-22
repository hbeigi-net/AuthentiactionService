using System;
using Application.Auth.Commands;
using FluentValidation;

namespace Application.Auth.Validators;

public class SignupValidator: AbstractValidator<Singup.Command>
{
    public SignupValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required")
            .EmailAddress().WithMessage("Invalid email format");

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required")
            .MinimumLength(6).WithMessage("Password must be at least 6 characters long");

    }
}
