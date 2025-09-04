using Application.User.Queries;
using Application.User.Commands;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Presentation.Controllers;

public class UserController : BaseController
{
  [HttpPut]
  public async Task<IActionResult> UpdateUser([FromBody] UpdateUser.Command command)
  {
    var result = await Mediator.Send(command);
    return result.ToActionResult();
  }

  [HttpPost("forgot-password")]
  [AllowAnonymous]

  public async Task<IActionResult> ForgotPassword([FromBody] ForgotPassword.Command command)
  {
    var result = await Mediator.Send(command);
    return result.ToActionResult();
  }

  [HttpPost("reset-password")]
  [AllowAnonymous]
  public async Task<IActionResult> ResetPassword([FromBody] ResetPassword.Command command)
  {
    var result = await Mediator.Send(command);
    return result.ToActionResult();
  }

  [HttpGet("info")]
  public async Task<IActionResult> GetUserInfo()
  {
    var result = await Mediator.Send(new GetUserInfo.Query());
    return result.ToActionResult();
  }
}