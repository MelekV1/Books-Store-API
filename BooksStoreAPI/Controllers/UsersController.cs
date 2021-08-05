using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using BooksStoreAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

namespace BooksStoreAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    //[Authorize]
    public class UsersController : ControllerBase
    {
        private readonly BookStoresDBContext _context;
        private readonly JWTSettings _jwtsettings;

        public UsersController(BookStoresDBContext context, IOptions<JWTSettings> jwtsettings)
        {
            _context = context;
            _jwtsettings = jwtsettings.Value;
        }

        // GET: api/Users
        [HttpGet("GetUsers")]
        public async Task<ActionResult<IEnumerable<User>>> GetUsers()
        {
            return await _context.Users.ToListAsync();
        }

        // GET: api/Users/5
        [HttpGet("GetUser/{id}")]
        public async Task<ActionResult<User>> GetUser(int id)
        {
            var user = await _context.Users.FindAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            return user;
        }

        // GET: api/Users?username=name&password=password
        //[HttpGet("GetUser")]
        //public async Task<ActionResult<User>> GetUser(string emailAddress, string password)
        //{
        //    var user =  await _context.Users.FirstOrDefaultAsync(u => u.EmailAddress == emailAddress && u.Password == password);

        //    if (user == null)
        //    {
        //        return NotFound();
        //    }

        //    return user;
        //}

        //GET: api/Users
        [HttpGet("GetUser")]
        public async Task<ActionResult<User>> GetUser()
        {
            string emailAddress = HttpContext.User.Identity.Name;
            var user = await _context.Users
                .Where(u => u.EmailAddress == emailAddress)
                .FirstOrDefaultAsync();

            user.Password = null;

            if (user == null)
            {
                return NotFound();
            }

            return user;
        }


        // GET: api/Users/5
        [HttpGet("GetUserDetails/{id}")]
        public async Task<ActionResult<User>> GetUserDetails(int id)
        {
            var user = await _context.Users.Include(u => u.Role)
                                            .Where(u => u.UserId == id)
                                            .FirstOrDefaultAsync();

            if (user == null)
            {
                return NotFound();
            }

            return user;
        }

        //POST : api/Users/Login
        [HttpPost("Login")]
        public async Task<ActionResult<UserWithToken>> Login([FromBody]User user)
        {
            user = await _context.Users
                .Include(u => u.Role)
                .Where(user => user.EmailAddress == user.EmailAddress
                && user.Password == user.Password)
                .FirstOrDefaultAsync();

            UserWithToken userWithToken = null;

            if (user != null)
            {
                RefreshToken refreshToken = GenerateRefreshToken();
                user.RefreshTokens.Add(refreshToken);
                await _context.SaveChangesAsync();

                userWithToken = new UserWithToken(user);
                userWithToken.RefreshToken = refreshToken.Token;

            }
            if (userWithToken == null)
                return NotFound();

            //Sign token here 
            userWithToken.AccessToken = GenerateAccessToken(user.UserId);
            return userWithToken;
        }

        //POST : api/Users/Refreshtoken
        [HttpPost("RefreshToken")]
        public async Task<ActionResult<UserWithToken>> RefreshToken([FromBody]RefreshRequest refreshRequest)
        {
            User user = await GetUserFromAccessToken(refreshRequest.AccessToken);
            if(user != null && ValidateRefreshToken(user, refreshRequest.RefreshToken))
            {
                UserWithToken userWithToken = new UserWithToken(user);
                userWithToken.AccessToken = GenerateAccessToken(user.UserId);

                return userWithToken;
            }
            return null;
        }

        private async Task<User> GetUserFromAccessToken(string accessToken)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_jwtsettings.SecretKey);

                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false
                };

                SecurityToken securityToken;
                var principle = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out securityToken);

                JwtSecurityToken jwtSecurityToken = securityToken as JwtSecurityToken;
                if (jwtSecurityToken != null && 
                    jwtSecurityToken.Header.Alg
                        .Equals(
                            SecurityAlgorithms.HmacSha256, 
                            StringComparison.InvariantCultureIgnoreCase))
                {
                    var userId = principle.FindFirst(ClaimTypes.Name)?.Value;

                    return await _context.Users.Include(u => u.Role)
                                        .Where(u => u.UserId == Convert.ToInt32(userId))
                                        .FirstOrDefaultAsync();
                }

            }
            catch (Exception)
            {
                return new User();
            }

            return new User();
        }

        private bool ValidateRefreshToken(User user, string refreshToken)
        {
            RefreshToken refreshTokenUser =
                _context.RefreshTokens.Where(rt => rt.Token == refreshToken)
                .OrderByDescending(rt => rt.ExpiryDate)
                .FirstOrDefault();

            if(refreshTokenUser != null && refreshTokenUser.UserId == user.UserId
                && refreshTokenUser.ExpiryDate>DateTime.UtcNow)
            {
                return true;
            }
            return false;
        }

        private RefreshToken GenerateRefreshToken()
        {
            RefreshToken refreshToken = new RefreshToken();
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                refreshToken.Token = Convert.ToBase64String(randomNumber);
            }
            refreshToken.ExpiryDate = DateTime.UtcNow.AddMonths(6);
            return refreshToken;
        }

        private string GenerateAccessToken(int userId)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtsettings.SecretKey);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    //new Claim(ClaimTypes.Name,user.EmailAddress)
                    new Claim(ClaimTypes.Name,Convert.ToString(userId))

                }),
                Expires = DateTime.UtcNow.AddMonths(6),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        // PUT: api/Users/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for
        // more details, see https://go.microsoft.com/fwlink/?linkid=2123754.
        [HttpPut("{id}")]
        public async Task<IActionResult> PutUser(int id, User user)
        {
            if (id != user.UserId)
            {
                return BadRequest();
            }

            _context.Entry(user).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!UserExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }

        // POST: api/Users
        // To protect from overposting attacks, enable the specific properties you want to bind to, for
        // more details, see https://go.microsoft.com/fwlink/?linkid=2123754.
        [HttpPost]
        public async Task<ActionResult<User>> PostUser(User user)
        {
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return CreatedAtAction("GetUser", new { id = user.UserId }, user);
        }

        // DELETE: api/Users/5
        [HttpDelete("{id}")]
        public async Task<ActionResult<User>> DeleteUser(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();

            return user;
        }

        private bool UserExists(int id)
        {
            return _context.Users.Any(e => e.UserId == id);
        }
    }
}
