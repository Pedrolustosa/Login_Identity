using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Login.API.Models;
using Login.API.Models.Authentication.Login;
using Login.API.Models.Authentication.SignUp;
using Login.Service.Models;
using Login.Service.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Login.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;

        public UserController(RoleManager<IdentityRole> roleManager,
                              UserManager<IdentityUser> userManager,
                              SignInManager<IdentityUser> signInManager,
                              IEmailService emailService,
                              IConfiguration configuration)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _configuration = configuration;
        }

        [HttpPost("Register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
                return StatusCode(StatusCodes.Status403Forbidden, new Response { Status = "Error", Message = "Exist User with this Email!" });

            IdentityUser identityUser = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username,
                TwoFactorEnabled = true
            };

            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(identityUser, registerUser.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Failed to Create" });
                }
                await _userManager.AddToRoleAsync(identityUser, role);

                var token = await _userManager.GenerateEmailConfirmationTokenAsync(identityUser);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "User", new { token, email = identityUser.Email });
                var message = new Message(new string[] { identityUser.Email! }, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"User Created and email sent to {registerUser.Email} successfully" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Role not exits!" });
            }

        }

        [HttpPost("Login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginUser loginUser)
        {
            var user = await _userManager.FindByNameAsync(loginUser.Username);
            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginUser.Password, false, true);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"We have sent an OTP to your Email {user.Email}" });
            }

            if (user != null && await _userManager.CheckPasswordAsync(user, loginUser.Password))
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                var userRoles = await _userManager.GetRolesAsync(user);
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }


                var jwtToken = GetToken(authClaims);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    SecurityTokenNoExpirationException = jwtToken.ValidTo
                });

            }
            return Unauthorized();
        }


        [HttpPost("LoginTwoFactor")]
        [AllowAnonymous]
        public async Task<IActionResult> LoginTwoFactor(string code, string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    var jwtToken = GetToken(authClaims);

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        SecurityTokenNoExpirationException = jwtToken.ValidTo
                    });

                }
            }
            return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "NotFound", Message = $"We have sent an OTP to your Email {user.Email}" });
        }
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return token;
        }


        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "Email verified with successfully!" });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "THis user don't exist" });
        }

        [HttpGet("SendEmail")]
        public IActionResult TestEmail()
        {
            var message = new Message(new string[] { "pedroeternalss@gmail.com" }, "Test", "<h1>Olá</h1>");
            _emailService.SendEmail(message);

            return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "Email sent Successfully" });
        }

    }
}