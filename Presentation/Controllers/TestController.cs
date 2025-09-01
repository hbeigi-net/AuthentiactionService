using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Presentation.Controllers;

// This controller inherits from BaseController which has [Authorize] attribute
// So all endpoints here require authentication by default
public class TestController : BaseController
{
  [HttpGet]
  public async Task<IActionResult> Get()
  {
    await Task.Delay(100);

    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var email = User.FindFirst(ClaimTypes.Email)?.Value;
    
    return Ok(new 
    { 
      Message = "You are logged in!",
      UserId = userId,
      Email = email,
      Timestamp = DateTime.UtcNow
    });
  }

  [HttpGet("protected-data")]
  public async Task<IActionResult> GetProtectedData()
  {
    await Task.Delay(100);
    
    return Ok(new
    {
      Message = "This is protected data",
      UserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value,
      AccessTime = DateTime.UtcNow
    });
  }
}