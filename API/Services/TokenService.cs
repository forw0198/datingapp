using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace API.Services;

public class TokenService(IConfiguration configuration) : ITokenService
{
    public string CreateToken(AppUser user)
    {
        // Implementation for creating JWT token
        var tokenKey = configuration["TokenKey"] ?? throw new 
        Exception("TokenKey is not configured");
        // Logic to create and return the token using the tokenKey and user information
        if(tokenKey.Length <64)
         throw new Exception("TokenKey must be at least 64 characters long");
         var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenKey));

         var claims = new List<Claim>
         {
             new Claim(ClaimTypes.Email, user.Email),
             new Claim(ClaimTypes.NameIdentifier, user.Id)
         };
         
         var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.Now.AddDays(7),
            SigningCredentials = creds
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
