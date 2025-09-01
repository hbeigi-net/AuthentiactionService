
using Application.Auth.DTOs;
using Application.Core;
using Application.Intefaces;
using MediatR;

namespace Application.Auth.Commands;

public class CompletePhoneSignup
{
  public class Command : IRequest<ApplicationResult<SigninResponseDTO>>
  {
    public required string PhoneNumber { get; set; }
    public required string OTP { get; set; }
  }

  public class Handler(
    IAuthService authService
  ) : IRequestHandler<Command, ApplicationResult<SigninResponseDTO>>
  {
    private readonly IAuthService _authService = authService;
    public async Task<ApplicationResult<SigninResponseDTO>> Handle(Command request, CancellationToken cancellationToken)
    {
      return await _authService.CompletePhoneSingup(request, cancellationToken);
    }
  }
}