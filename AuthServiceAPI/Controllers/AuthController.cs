using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;
using MongoDB.Driver;
using MongoDB.Bson;

namespace AuthServiceAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly string _secret;
    private readonly string _issuer;
    private readonly IMongoCollection<User> _users;
    private readonly IConfiguration _config;
    
    public AuthController(ILogger<AuthController> logger, IConfiguration config)
    {
        _logger = logger;
        _secret = config["Secret"] ?? "Secret missing";
        _issuer = config["Issuer"] ?? "Issuer missing";
        _config = config;
        
        var mongoClient = new MongoClient(_config["ConnectionURI"]);
        _logger.LogInformation($"ConnectionURI: {_config["ConnectionURI"]}");

        var database = mongoClient.GetDatabase(_config["DatabaseName"]);
        _logger.LogInformation($"Database: {_config["DatabaseName"]}");

        _users = database.GetCollection<User>(_config["CollectionName"]);
        _logger.LogInformation($"Collection: {_config["CollectionName"]}");

    }

    // Login POST - Godkender legitimationsoplysninger og udsteder JWT-token
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel login)
    {
        _logger.LogInformation($"Login: {login.Username} - {login.Password}");
        var user = await _users.Find(u => u.Username == login.Username).FirstOrDefaultAsync<User>();

        _logger.LogInformation($"{user.Username}, {user.Password}");

        if (user == null || user.Username != login.Username)
        {
            return Unauthorized();
        }
        var token = GenerateJwtToken(user.Username);

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
