using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace Presentation.Controllers;

[ApiController]
[Route("v{version:apiVersion}/[controller]")]
public class BaseController() : ControllerBase
{
  private IMediator? _mediator;

  protected IMediator Mediator => _mediator
    ??= HttpContext.RequestServices.GetService<IMediator>()
    ?? throw new ArgumentException("MediatR not Found");


}
