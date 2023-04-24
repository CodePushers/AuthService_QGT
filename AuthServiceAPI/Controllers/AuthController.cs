using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;

namespace AuthServiceAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly string _secret;
    private readonly string _issuer;


    public AuthController(ILogger<AuthController> logger, IConfiguration config)
    {
        _logger = logger;
        _secret = config["Secret"] ?? "Secret missing";
        _issuer = config["Issuer"] ?? "Issuer missing";
    }

    // Login POST - Godkender legitimationsoplysninger og udsteder JWT-token
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel login)
    {
        if (login.Password != "password")
        {
            return Unauthorized();
        }
        var token = GenerateJwtToken(login.Username);
        return Ok(new { token });
    }

    [AllowAnonymous]
    [HttpPost("validate")]
    public async Task<IActionResult> ValidateJwtToken([FromBody] string? token)
    {
        _logger.LogInformation($"Token: {token}");

        if (token.IsNullOrEmpty())
            return BadRequest("Invalid token submited.");

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_secret);

        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;

            var accountId = jwtToken.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
            
            return Ok(accountId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, ex.Message);
            return StatusCode(404);
        }
    }
    private string GenerateJwtToken(string username)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));

        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
           new Claim(ClaimTypes.NameIdentifier, username),
        };

        if (username == "admin")
        {
            claims.Add(new Claim(ClaimTypes.Role, "admin"));
            claims.Add(new Claim("admin", "true"));
        }

        var token = new JwtSecurityToken(
            _issuer,
            "http://localhost",
            claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials);

        _logger.LogInformation($"Generate token info: Secret: {_secret}, Issuer: {_issuer}");

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
