using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Login.API.Controllers
{
    [Authorize(Roles = "User")]
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {

        [HttpGet("Employees")]
        public IEnumerable<string> Get()
        {
            return new List<string> { "PEdro1", "pedro2", "pEdro3" };
        }

    }
}