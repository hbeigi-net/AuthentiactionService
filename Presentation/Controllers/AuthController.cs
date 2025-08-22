using System;
using Application.Auth.Commands;
using Application.Auth.DTOs;
using Application.Core;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace Presentation.Controllers;

public class AuthController : BaseController
{
  [HttpPost("signup")]
  [AllowAnonymous]
  public async Task<IActionResult> SingUp([FromBody] Singup.Command command)
  {
    var result = await Mediator.Send(command);

    return result.ToActionResult();
  }
  [HttpPost("signin")]
  [AllowAnonymous]
  public async Task<IActionResult> SignIn([FromBody] SignIn.Command command)
  {
    var result = await Mediator.Send(command);

    return result.ToActionResult();
  }


}
