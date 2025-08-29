using Application.Core;
using Application.Intefaces;
using MediatR;

namespace Application.Auth.Commands;

public class VerifyEmail 
{
  public record Command(string Email, string Token) : IRequest<ApplicationResult<bool>>;

  public class Handler(
    IAuthService authService
  ) : IRequestHandler<Command, ApplicationResult<bool>>
  {
    public async Task<ApplicationResult<bool>> Handle(Command request, CancellationToken cancellationToken)
    {
      return await authService.ConfirmEmailAsync(request.Email, request.Token);
    }
  }
}