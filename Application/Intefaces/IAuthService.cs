using System;
using Application.Auth.Commands;
using Application.Auth.DTOs;
using Application.Core;
using FluentResults;
using MediatR;

namespace Application.Intefaces;

public interface IAuthService
{
  Task<ApplicationResult<SigninResponseDTO>> SignInAsync(SignIn.Command request);
  Task<ApplicationResult<SingupResponseDTO>> SignUpAsync(Singup.Command request);
  Task<ApplicationResult<SingupResponseDTO>> PhoneSignUpAsync(PhoneSignup.Command request, CancellationToken cancellationToken);
  Task<ApplicationResult<SigninResponseDTO>> CompletePhoneSingup(CompletePhoneSignup.Command request, CancellationToken cancellation);
  Task<ApplicationResult<SigninResponseDTO>> PhoneSignInAsync(PhoneSignin.Command request);
  Task<ApplicationResult<bool>> RequestSigninOtp(RequestSinginOtp.Command request);
  Task<ApplicationResult<RefreshTokenResponseDto>> RefreshToken(string refreshToken);
  Task<ApplicationResult<bool>> LogoutAsync(string refreshToken, CancellationToken cancellationToken);
  Task<ApplicationResult<bool>> RevokeAllTokensAsync(string userId, CancellationToken cancellationToken);
  Task<ApplicationResult<bool>> ConfirmEmailAsync(string email, string token);
  Task<ApplicationResult<Unit>> ForgotPasswordAsync(string email);
  Task<ApplicationResult<bool>> ChangePasswordAsync(ChangePassword.Command request, CancellationToken cancellationToken);
  Task<ApplicationResult<bool>> ResendVerificationEmailAsync(string email);

  //Task<Result> ResetPasswordAsync(ResetPasswordRequest request);
}
