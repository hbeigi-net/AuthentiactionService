using System;
using Application.Auth.DTOs;
using FluentResults;
using MediatR;

namespace Application.Auth.Queries;

public class GetUserInfo
{
  public class Query : IRequest<Result<UserInfoDTO>>
  {
    public Guid UserId { get; set; }
  }

  public class Handler : IRequestHandler<Query, Result<UserInfoDTO>>
  {
    public Task<Result<UserInfoDTO>> Handle(Query request, CancellationToken cancellationToken)
    {
      // Logic for fetching user info
      throw new NotImplementedException();
    }
  }
}
