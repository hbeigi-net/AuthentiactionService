
using Application.Core;
using Application.Intefaces;
using MediatR;

namespace Application.Auth.Commands;

public class ResendVerificationEmail
{
  public record Command(string Email) : IRequest<ApplicationResult<bool>>;

  public class Handler(
    IAuthService authService
  ) : IRequestHandler<Command, ApplicationResult<bool>>
  {
    public async Task<ApplicationResult<bool>> Handle(Command request, CancellationToken cancellationToken)
    {
      return await authService.ResendVerificationEmailAsync(request.Email);
    }
  }
}