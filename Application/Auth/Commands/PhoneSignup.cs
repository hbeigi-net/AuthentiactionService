using System;
using Application.Auth.DTOs;
using Application.Core;
using Application.Interfaces;
using FluentResults;
using FluentValidation;
using MediatR;

namespace Application.Auth.Commands;

public class PhoneSignup
{
  public class Command : IRequest<ApplicationResult<SingupResponseDTO>>
  {
    public required string PhoneNumber { get; set; }
  }

  public class Handler(
    IAuthService authService
  ) : IRequestHandler<Command, ApplicationResult<SingupResponseDTO>>
  { 
    private readonly IAuthService _authService = authService;

    public async Task<ApplicationResult<SingupResponseDTO>> Handle(Command request, CancellationToken cancellationToken)
    {
      return await _authService.PhoneSignUpAsync(request, cancellationToken);
    }
  }
}