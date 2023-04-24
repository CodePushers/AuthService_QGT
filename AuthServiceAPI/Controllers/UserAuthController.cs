using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace AuthService_API.Controllers;

[ApiController]
[Route("[controller]")]
public class UserAuthController : ControllerBase
{
    private readonly ILogger<UserAuthController> _logger;

    public UserAuthController(ILogger<UserAuthController> logger, IConfiguration config)
    {
        _logger = logger;
    }

    [Authorize]
    [HttpGet("all")]
    public async Task<IActionResult> Get()
    {
        return Ok("You're authorized");
    }
}
