using System;
using FluentResults;
using Microsoft.AspNetCore.Mvc;

namespace Application.Core;

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
      return new OkObjectResult(result.ToApiResponse());
    }

    if (result.StatusCode == 401)
    {
      return new UnauthorizedObjectResult(result.ToApiResponse());
    }

    return new BadRequestObjectResult(result.ToApiResponse());
  }

}
