using System;
using Application.Auth.Commands;
using Application.Auth.DTOs;
using Application.Core;
using Microsoft.AspNetCore.Mvc;

namespace Presentation.Controllers;

public class AuthController : BaseController
{
  [HttpPost("signin")]
  public async Task<ApiResponse<SigninResponseDTO>>  SignIn([FromBody] SignIn.Command command)
  {
    var result = await Mediator.Send(command);

    return result.ToApiResponse();
  }
  [HttpPost("signup")]
  public async Task<ApiResponse<SingupResponseDTO>>  SingUp([FromBody] Singup.Command command)
  {
    var result = await Mediator.Send(command);

    return result.ToApiResponse();
  }
}
