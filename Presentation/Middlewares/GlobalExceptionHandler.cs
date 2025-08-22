using System;
using FluentResults;
using Application.Core;
using FluentValidation;
namespace Presentation.Middlewares;

internal sealed class GlobalExceptionHandler(
  RequestDelegate next,
  ILogger<GlobalExceptionHandler> logger,
  IHostEnvironment hostEnvironment
)
{
  private readonly IHostEnvironment _hostEnvironment = hostEnvironment;
  private readonly RequestDelegate _next = next;
  private readonly ILogger<GlobalExceptionHandler> _logger = logger;
  public async Task InvokeAsync(HttpContext httpContext)
  {
    try
    {
      await _next(httpContext);
    }
    catch (Exception exp)
    {
      //_logger.LogError(httpContext.TraceIdentifier, exp);
      int statusCode = exp.GetType().Name switch
      {
        "ApplicationException" => StatusCodes.Status400BadRequest,
        "ValidationException" => StatusCodes.Status400BadRequest,
        _ => StatusCodes.Status500InternalServerError,
      };


      var errorResponse = new ApiResponse<object>
      {
        ErrorMessage = exp.Message,
        StackTrace = _hostEnvironment.IsDevelopment() ?  exp.StackTrace : null,
        IsSuccess = false,
        Errors = null,
        Result = null,
      };

      if(exp is ValidationException validationException) {
        errorResponse.Errors = validationException.Errors
          .GroupBy(e => e.PropertyName)
          .ToDictionary(
              g => g.Key, 
              g => g.Select(e => e.ErrorMessage).ToArray()
          );

        errorResponse.ErrorMessage = "Validation Error";
      }

      httpContext.Response.ContentType = "application/json";
      httpContext.Response.StatusCode = statusCode;
      await httpContext.Response.WriteAsJsonAsync(errorResponse);
    }
  }
}
