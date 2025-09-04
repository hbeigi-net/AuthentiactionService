
using System.Text;
using Application.Core;
using Application.Interfaces;
using Application.User.DTOs;
using AutoMapper;
using MediatR;

namespace Application.User.Commands;

public class UpdateUser
{
  public class Command : UpdateUserDto, IRequest<ApplicationResult<bool>>
  { }
  public class Handler(
    IApplicationUserRepository userRepository,
    ICurrentUserService currentUserService,
    IMapper mapper
  ) : IRequestHandler<Command, ApplicationResult<bool>>
  {
    async Task<ApplicationResult<bool>> IRequestHandler<Command, ApplicationResult<bool>>.Handle(Command request, CancellationToken cancellationToken)
    {
      var userId = currentUserService.GetUserId();

      if (userId is null)
      {
        return ApplicationResult<bool>.Fail("unAuthenticated", 401);
      }

      var user = await userRepository.GetByIdAsync(userId!.Value);

      if (user is null)
      {
        return ApplicationResult<bool>.Fail("User not found", 403);
      }


      mapper.Map(request, user);
      await userRepository.UpdateAsync(user);

      return ApplicationResult<bool>.Ok(true);
    }
  }
}