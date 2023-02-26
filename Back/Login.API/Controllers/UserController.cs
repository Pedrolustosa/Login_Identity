using Login.API.Models;
using Login.API.Models.Authentication.SignUp;
using Login.Service.Models;
using Login.Service.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Login.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;

        public UserController(RoleManager<IdentityRole> roleManager,
                              UserManager<IdentityUser> userManager,
                              IEmailService emailService)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _emailService = emailService;
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
                UserName = registerUser.Username
            };

            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(identityUser, registerUser.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Failed to Create" });
                }
                await _userManager.AddToRoleAsync(identityUser, role);
                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "User Created!" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Role not exits!" });
            }

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