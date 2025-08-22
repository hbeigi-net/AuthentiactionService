using System;
using Application.Auth.DTOs;
using Application.Core;
using Application.Intefaces;
using FluentResults;
using MediatR;

namespace Application.Auth.Commands;

public class SignIn
{
  public class Command : IRequest<Result<SigninResponseDTO>>
  {
    public required string Email { get; set; }
    public required string Password { get; set; }
    public bool RememberMe { get; set; }
    public string? DeviceInfo { get; set; }
    public string? IpAddress { get; set; }
  }

  public class Handler(
    IAuthService authService
  ) : IRequestHandler<Command, Result<SigninResponseDTO>>
  {
    private readonly IAuthService _authService = authService;

    public async Task<Result<SigninResponseDTO>> Handle(Command request, CancellationToken cancellationToken)
    {
      return await _authService.SignInAsync(request);
    }
  }
}