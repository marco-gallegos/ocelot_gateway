using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private IOptions<Audience> _settings;

        public AuthController(IOptions<Audience> settings)
        {
            this._settings = settings;
        }

        [HttpGet]
        public ActionResult Get(string name, string pwd)
        {
            Console.WriteLine($"{name} || {pwd}");

            if (name == "catcher" && pwd == "123")
            {

                var now = DateTime.UtcNow;

                var claims = new Claim[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, name),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, now.ToUniversalTime().ToString(), ClaimValueTypes.Integer64)
                };

                var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_settings.Value.Secret));
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = signingKey,
                    ValidateIssuer = true,
                    ValidIssuer = _settings.Value.Iss,
                    ValidateAudience = true,
                    ValidAudience = _settings.Value.Aud,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    RequireExpirationTime = true,

                };

                var jwt = new JwtSecurityToken(
                    issuer: _settings.Value.Iss,
                    audience: _settings.Value.Aud,
                    claims: claims,
                    notBefore: now,
                    expires: now.Add(TimeSpan.FromMinutes(2)),
                    signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
                );
                var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
                var responseJson = new
                {
                    access_token = encodedJwt,
                    expires_in = (int)TimeSpan.FromMinutes(2).TotalSeconds
                };

                return Ok(responseJson);
            }
            else
            {
                return Ok(new { mal = "yes" });
            }
        }
    }

    public class Audience
    {
        public string Secret { get; set; }
        public string Iss { get; set; }
        public string Aud { get; set; }
    }
}
