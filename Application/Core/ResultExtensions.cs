using System;
using FluentResults;
using Microsoft.AspNetCore.Mvc;

namespace Application.Core;

public static class ResultExtensions
{
  public static ApiResponse<T> ToApiResponse<T>(this Result<T> result)
  {

    return new ApiResponse<T>
    {
      IsSuccess = result.IsSuccess,
            ErrorMessage = result.IsFailed ? string.Join("\n", result.Errors.Select(err => err.Message))  : null,
      Result = result.IsSuccess ? result.Value : default,
    };
  }

  //public static ApiResponse<object> ToApiResponse(this Result<object> result)
  //{
  //  return new ApiResponse<object>
  //  {
  //    IsSuccess = result.IsSuccess,
  //    ErrorMessage = result.IsFailed ? string.Join("\n", result.Errors.Select(err => err.Message))  : null,
  //    Result = result.IsSuccess ? result.Value : default,
  //  };
  //}

  public static IActionResult ToActionResult<T>(this Result<T> result)
  {
    if (result.IsSuccess)
    {
      return new OkObjectResult(new ApiResponse<T>
      {
        IsSuccess = true,
        Result = result.Value,
        Errors = null,
      });
    }

    return new BadRequestObjectResult(new ApiResponse<T>
    {
      IsSuccess = false,
      ErrorMessage = string.Join("\n", result.Errors.Select(err => err.Message)),
      Errors = null,
    });
  }
}
