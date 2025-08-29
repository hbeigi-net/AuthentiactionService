using Microsoft.AspNetCore.Mvc;
using Presentation.Models;
using Application.Core;

namespace Presentation.Extensions;

public static class ResultExtensions
{
  public static ApiResponse<T> ToApiResponse<T>(this ApplicationResult<T> result)
  {

    return new ApiResponse<T>
    {
      IsSuccess = result.IsSuccess,
      ErrorMessage = result.ErrorMessage,
      Result = result.IsSuccess ? result.Value : default,
    };
  }

  public static IActionResult ToActionResult<T>(this ApplicationResult<T> result)
  {
    if (result.IsSuccess)
    {
      if(result.StatusCode == 302) {
        return new RedirectResult(result.RedirectUrl!, true);
      }
      
      return new OkObjectResult(result.ToApiResponse());
    }

    if (result.StatusCode == 401)
    {
      return new UnauthorizedObjectResult(result.ToApiResponse());
    }

    return new BadRequestObjectResult(result.ToApiResponse());
  }

}
