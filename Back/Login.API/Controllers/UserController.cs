using Login.API.Models;
using Login.API.Models.Authentication.SignUp;
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
        private readonly IConfiguration _configuration;

        public UserController(IConfiguration configuration,
                              RoleManager<IdentityRole> roleManager,
                              UserManager<IdentityUser> userManager)
        {
            _configuration = configuration;
            _roleManager = roleManager;
            _userManager = userManager;
        }

        [HttpPost("Register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
                return StatusCode(StatusCodes.Status403Forbidden, new Response { Status = "Error", Message = "Exist User!" });

            IdentityUser identityUser = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username
            };

            if(await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(identityUser, registerUser.Password);
                if(!result.Succeeded)
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
    }
}