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
        _config = config;

        _secret = config["Secret"] ?? "Secret missing";
        _issuer = config["Issuer"] ?? "Issue'er missing";
        
        // Client
        var mongoClient = new MongoClient(_config["ConnectionURI"]);
        _logger.LogInformation($"[*] CONNECTION_URI: {_config["ConnectionURI"]}");

        // Database
        var database = mongoClient.GetDatabase(_config["DatabaseName"]);
        _logger.LogInformation($"[*] DATABASE: {_config["DatabaseName"]}");

        // Collection
        _users = database.GetCollection<User>(_config["CollectionName"]);
        _logger.LogInformation($"[*] COLLECTION: {_config["CollectionName"]}");

    }

    // Login POST - Godkender legitimationsoplysninger og udsteder JWT-token
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel login)
    {
        _logger.LogInformation("Metoden: Login(LoginModel login) kaldt klokken: {DT}", DateTime.UtcNow.ToLongTimeString());

        User user = await _users.Find(u => u.Username == login.Username).FirstOrDefaultAsync<User>();
        _logger.LogInformation($"Loginoplysninger\n\tUsername: {user.Username}\n\tPassword: {user.Password}");

        if (user == null || user.Username != login.Username)
        {
            return Unauthorized();
        }

        var token = GenerateJwtToken(user.Username);

        return Ok(new { token });
    }

    // Genererer en JWT-token når en kendt bruger logger på.
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
