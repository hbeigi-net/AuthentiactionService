using System;
using FluentResults;

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

  public static ApiResponse<object> ToApiResponse(this Result<object> result)
  {
    return new ApiResponse<object>
    {
      IsSuccess = result.IsSuccess,
      ErrorMessage = result.IsFailed ? string.Join("\n", result.Errors.Select(err => err.Message))  : null,
      Result = result.IsSuccess ? result.Value : default,
    };
  }
}
