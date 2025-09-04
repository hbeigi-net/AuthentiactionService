

using Application.Core;
using Application.Interfaces;
using Application.User.DTOs;
using MediatR;

namespace Application.User.Queries;

public class GetUserInfo
{
  public class Query : IRequest<ApplicationResult<UserInfoDto>>
  {
  }

  public class Handler(
    ICurrentUserService currentUserService,
    IApplicationUserRepository userRepository
  ) : IRequestHandler<Query, ApplicationResult<UserInfoDto>>
  {
    public async Task<ApplicationResult<UserInfoDto>> Handle(Query request, CancellationToken cancellationToken)
    {
      var userId = currentUserService.GetUserId();
      if (userId is null)
      {
        return ApplicationResult<UserInfoDto>.Fail("User not found");
      }

      var user = await userRepository.GetUserInfoAsync(userId!.Value);
      if (user is null)
      {
        return ApplicationResult<UserInfoDto>.Fail("User not found");
      }
      
      return ApplicationResult<UserInfoDto>.Ok(user);
    }


  }
}
