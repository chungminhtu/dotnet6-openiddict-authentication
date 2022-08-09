using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;

namespace authServer.Controllers;
[Route("api/[controller]")]
[ApiController]
public class TestController : ControllerBase
{
    [HttpGet]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public IActionResult Test()
    {
        var userId = HttpContext.User.FindFirst(OpenIddictConstants.Claims.Subject)?.Value;
        var userName = HttpContext.User.FindFirst(OpenIddictConstants.Claims.Username)?.Value;
        var role = HttpContext.User.FindFirst(OpenIddictConstants.Claims.Role)?.Value;
        return Ok(new { Id = userId, UserName = userName, Role = role });
    }
}