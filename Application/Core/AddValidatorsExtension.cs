using Application.Auth.Commands;
using Application.Auth.Validators;
using Application.User.Commands;
using Application.User.Validators;
using FluentValidation;
using Microsoft.Extensions.DependencyInjection;

namespace Application.Core;

public static class ValidatorsExtension
{
  public static IServiceCollection AddValidators(this IServiceCollection services)
  {
    services.AddScoped<IValidator<Singup.Command>, SignupValidator>();
    services.AddScoped<IValidator<SignIn.Command>, SigninValidator>();
    services.AddScoped<IValidator<ChangePassword.Command>, ChangePasswordValidator>();
    services.AddScoped<IValidator<PhoneSignup.Command>, MobileSignupValidator>();
    services.AddScoped<IValidator<RequestSinginOtp.Command>, RequestSigninOtpValidator>();
    services.AddScoped <IValidator<PhoneSignin.Command>, PhoneSigninValidator>();

    services.AddScoped<IValidator<ResetPassword.Command>, ResetPasswordValidator>();
    return services;
  }
}
