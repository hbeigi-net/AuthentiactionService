
using Application.Core;
using Application.Interfaces;
using MediatR;

namespace Application.Auth.Commands;

public class RequestSinginOtp
{
  public class Command : IRequest<ApplicationResult<bool>>
  {
    public required string PhoneNumber { get; set; }
  }

  public class Handler(
    IAuthService authService
  ) : IRequestHandler<Command, ApplicationResult<bool>>
  {
    private readonly IAuthService _authService = authService;
    public async Task<ApplicationResult<bool>> Handle(Command request, CancellationToken cancellationToken)
    {

      return await _authService.RequestSigninOtp(request);
    }
  }
}