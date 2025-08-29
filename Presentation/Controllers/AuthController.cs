using Application.Auth.Commands;
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

  [HttpPost("refresh-token")]
  [AllowAnonymous]
  public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenCommand.Command command)
  {
    var result = await Mediator.Send(command);
    return result.ToActionResult();
  }

  [HttpPost("change-password")]
  public async Task<IActionResult> ChangePassword([FromBody] ChangePassword.Command command) 
  {
     var result = await  Mediator.Send(command);  
     return result.ToActionResult();
  }

  [HttpPost("logout")] 
  public async Task<IActionResult> Logout([FromBody] Logout.Command command)
  {
    var result = await Mediator.Send(command);
    return result.ToActionResult();
  }

  [HttpGet("verify-email")]
  [AllowAnonymous]
  public async Task<IActionResult> VerifyEmail([FromQuery] string email, [FromQuery] string token)
  {
    var result = await Mediator.Send(new VerifyEmail.Command(email, token));
    return result.ToActionResult();
  }

  [HttpPost("resend-verification-email")]
  [AllowAnonymous]
  public async Task<IActionResult> ResendVerificationEmail([FromBody] ResendVerificationEmail.Command command)
  {
    var result = await Mediator.Send(command);
    return result.ToActionResult();
  }
}
