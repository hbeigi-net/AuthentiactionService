
using Application.Core;
using Application.Intefaces;
using MediatR;

namespace Application.Auth.Commands;

public class ChangePassword
{
  public class Command : IRequest<ApplicationResult<bool>>
  {
    public required string CurrentPassword { get; set; }
    public required string NewPassword { get; set; }
  }

  public class Handler(
    IAuthService authService
  ) : IRequestHandler<Command, ApplicationResult<bool>>

  {
    private readonly IAuthService _authService = authService;
    public async Task<ApplicationResult<bool>> Handle(Command request, CancellationToken cancellationToken)
    {
      return await _authService.ChangePasswordAsync(request);
    }
  }
}