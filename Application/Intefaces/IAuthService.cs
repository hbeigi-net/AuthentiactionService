using System;
using Application.Auth.Commands;
using Application.Auth.DTOs;
using FluentResults;

namespace Application.Intefaces;

public interface IAuthService
{
  Task<Result<SigninResponseDTO>> SignInAsync(SignIn.Command request);
  Task<Result<SingupResponseDTO>> SignUpAsync(Singup.Command request);
  //Task<Result<LoginResponse>> RefreshTokenAsync(RefreshTokenRequest request);
  Task<Result> LogoutAsync(string refreshToken);
  Task<Result> RevokeAllTokensAsync(Guid userId);
  Task<Result> ConfirmEmailAsync(string userId, string token);
  Task<Result> ForgotPasswordAsync(string email);
  //Task<Result> ResetPasswordAsync(ResetPasswordRequest request);
}
