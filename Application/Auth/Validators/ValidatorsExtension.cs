using System;
using Application.Auth.Commands;
using FluentValidation;
using Microsoft.Extensions.DependencyInjection;

namespace Application.Auth.Validators;

public static class ValidatorsExtension
{
  public static IServiceCollection AddValidators(this IServiceCollection services)
  {
    services.AddScoped<IValidator<Singup.Command>, SignupValidator>();
    services.AddScoped<IValidator<SignIn.Command>, SigninValidator>();
    services.AddScoped<IValidator<ChangePassword.Command>, ChangePasswordValidator>();

    return services;
  }
}
