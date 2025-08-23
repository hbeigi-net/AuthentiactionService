using Application.Auth.DTOs;
using Application.Core;
using Application.Intefaces;
using FluentResults;
using MediatR;

namespace Application.Auth.Commands;

public class RefreshTokenCommand {

  public class Command: IRequest<ApplicationResult<RefreshTokenResponseDto>>
  {
    public required string RefreshToken {get; set;}
  }

  public class Handler(
    IAuthService authService
  ): IRequestHandler<Command, ApplicationResult<RefreshTokenResponseDto>>
  {
    private readonly IAuthService _authService = authService;

    public async Task<ApplicationResult<RefreshTokenResponseDto>> Handle(Command request, CancellationToken cancellationToken)
    {
      return await _authService.RefreshToken(request.RefreshToken);
    }
  }
}