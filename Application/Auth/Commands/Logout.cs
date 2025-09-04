

using Application.Core;
using Application.Interfaces;
using MediatR;

namespace Application.Auth.Commands;

public class Logout
{
  public class Command : IRequest<ApplicationResult<bool>>
  {
    public required string RefreshToken { get; set; }
  }

  public class Handler(
    IAuthService authService
  ) : IRequestHandler<Command, ApplicationResult<bool>>
  {
    public async Task<ApplicationResult<bool>> Handle(Command request, CancellationToken cancellationToken)
    {
      return await authService.LogoutAsync(request.RefreshToken, cancellationToken);
    }
  }
}