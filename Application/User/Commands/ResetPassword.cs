using Application.Core;
using Application.Interfaces;
using MediatR;

namespace Application.User.Commands;

public class ResetPassword
{
  public class Command : IRequest<ApplicationResult<bool>>
  {
    public required string Email { get; set; }
    public required string Token { get; set; }
    public required string NewPassword { get; set; }
  }

  public class Handler
  (
    IAuthService authService
  ) : IRequestHandler<Command, ApplicationResult<bool>>
  {
    private readonly IAuthService _authService = authService;
    public async Task<ApplicationResult<bool>> Handle(Command request, CancellationToken cancellationToken)
    {
      return await _authService.ResetPasswordAsync(request);
    }
  }
}