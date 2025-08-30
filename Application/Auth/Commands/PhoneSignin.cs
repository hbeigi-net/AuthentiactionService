using Application.Auth.DTOs;
using Application.Core;
using Application.Intefaces;
using MediatR;

namespace Application.Auth.Commands;

public class PhoneSignin 
{
  public class Command : IRequest<ApplicationResult<PhoneSigninResponseDto>>
  {
    public required string PhoneNumber { get; set; }
    public required string OTP { get; set; }
  }

  public class Handler(
    IAuthService authService
  ) : IRequestHandler<Command, ApplicationResult<PhoneSigninResponseDto>>
  {
    private readonly IAuthService _authService = authService;
    public async Task<ApplicationResult<PhoneSigninResponseDto>> Handle(Command request, CancellationToken cancellationToken)
    {
       return await _authService.PhoneSignInAsync(request);
    }
  }

}