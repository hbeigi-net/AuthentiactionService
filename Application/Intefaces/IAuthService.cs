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
  Task<ApplicationResult<RefreshTokenResponseDto>> RefreshToken(string refreshToken);
  Task<ApplicationResult<bool>> LogoutAsync(string refreshToken, CancellationToken cancellationToken);
  Task<ApplicationResult<bool>> RevokeAllTokensAsync(string userId, CancellationToken cancellationToken);
  Task<ApplicationResult<Unit>> ConfirmEmailAsync(string userId, string token);
  Task<ApplicationResult<Unit>> ForgotPasswordAsync(string email);
  Task<ApplicationResult<bool>> ChangePasswordAsync(ChangePassword.Command request, CancellationToken cancellationToken);
  //Task<Result> ResetPasswordAsync(ResetPasswordRequest request);
}
