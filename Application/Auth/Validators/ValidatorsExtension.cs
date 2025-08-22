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
    // Add other validators here as needed
    return services;
  }
}
